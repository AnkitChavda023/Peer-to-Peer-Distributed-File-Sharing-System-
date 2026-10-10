#include <iostream>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <sstream>
#include <openssl/sha.h>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <chrono>
#include <atomic>
#include <csignal>
#include "common.h"

using namespace std;

struct UserInfo {
    string userId;
    string passwordHash;
    string currentIp;
    int currentPort = -1;
    bool loggedIn = false;
};

struct GroupInfo {
    string groupId;
    string owner;
    unordered_set<string> members;
    unordered_set<string> pendingRequests;
};

struct SeederInfo {
    string userId;
    string ip;
    int port;
    vector<bool> haveChunk;
};

struct FileMetaData {
    string groupId;
    string filename;
    string fileKey;
    string fileSHA;
    long long fileSize = 0;
    long long totalChunks = 0;
    vector<string> chunkHashes;
    string ownerId;
    vector<SeederInfo> seeders;
};

struct TrackerState {
    unordered_map<string, UserInfo> users;
    unordered_map<string, GroupInfo> groups;
    unordered_map<string, FileMetaData> files;
};

static const long long CHUNK_SIZE = 512LL * 1024LL;

TrackerState state;
mutex dataLock;

string myIp, peerIp;
int myPort = -1, peerPort = -1;

mutex peerLock;
int peerSock = -1;
atomic<bool> peerConnected(false);

string sha1Hex(const unsigned char *hash) {
    char buf[41];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(buf + (i * 2), "%02x", hash[i]);
    buf[40] = '\0';
    return string(buf);
}

string hashPassword(const string &password) {
    unsigned char h[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)password.data(), password.size(), h);
    return sha1Hex(h);
}

vector<string> tokenize(const string &command) {
    vector<string> tokens;
    stringstream ss(command);
    string tok;
    while (getline(ss, tok, ' ')) {
        if (!tok.empty()) tokens.push_back(tok);
    }
    return tokens;
}

string join(const vector<string> &parts, char sep) {
    string out;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

bool forwardToPeer(const string &syncMsg) {
    lock_guard<mutex> lock(peerLock);
    if (!peerConnected || peerSock < 0) return false;
    if (!sendFramed(peerSock, syncMsg)) {
        peerConnected = false;
        close(peerSock);
        peerSock = -1;
        return false;
    }
    return true;
}

string bitfieldToString(const vector<bool> &v) {
    string s(v.size(), '0');
    for (size_t i = 0; i < v.size(); i++) if (v[i]) s[i] = '1';
    return s;
}

vector<bool> stringToBitfield(const string &s) {
    vector<bool> v(s.size(), false);
    for (size_t i = 0; i < s.size(); i++) v[i] = (s[i] == '1');
    return v;
}

string buildSnapshot() {
    lock_guard<mutex> lock(dataLock);
    ostringstream out;

    out << "USERS " << state.users.size() << "\n";
    for (auto &kv : state.users) {
        out << kv.second.userId << " " << kv.second.passwordHash << "\n";
    }

    out << "GROUPS " << state.groups.size() << "\n";
    for (auto &kv : state.groups) {
        auto &g = kv.second;
        out << g.groupId << " " << g.owner << " " << g.members.size();
        for (auto &m : g.members) out << " " << m;
        out << " " << g.pendingRequests.size();
        for (auto &p : g.pendingRequests) out << " " << p;
        out << "\n";
    }

    out << "FILES " << state.files.size() << "\n";
    for (auto &kv : state.files) {
        auto &f = kv.second;
        out << f.fileKey << "\n";
        out << f.groupId << "\n" << f.filename << "\n" << f.fileSHA << "\n"
            << f.ownerId << "\n" << f.fileSize << " " << f.totalChunks << "\n";
        string pieces;
        for (size_t i = 0; i < f.chunkHashes.size(); i++) {
            if (i) pieces += ",";
            pieces += f.chunkHashes[i];
        }
        out << pieces << "\n";
        out << f.seeders.size() << "\n";
        for (auto &s : f.seeders) {
            out << s.userId << " " << s.ip << " " << s.port << " "
                << bitfieldToString(s.haveChunk) << "\n";
        }
    }

    return out.str();
}

void mergeSnapshot(const string &snap) {
    istringstream in(snap);
    string tag;
    long long count;

    lock_guard<mutex> lock(dataLock);

    in >> tag >> count;
    for (long long i = 0; i < count; i++) {
        string userId, passHash;
        in >> userId >> passHash;
        if (state.users.find(userId) == state.users.end()) {
            UserInfo u;
            u.userId = userId;
            u.passwordHash = passHash;
            state.users[userId] = u;
        }
    }

    in >> tag >> count;
    for (long long i = 0; i < count; i++) {
        string groupId, owner;
        size_t memberCount;
        in >> groupId >> owner >> memberCount;
        vector<string> members(memberCount);
        for (auto &m : members) in >> m;
        size_t pendingCount;
        in >> pendingCount;
        vector<string> pending(pendingCount);
        for (auto &p : pending) in >> p;

        auto it = state.groups.find(groupId);
        if (it == state.groups.end()) {
            GroupInfo g;
            g.groupId = groupId;
            g.owner = owner;
            for (auto &m : members) g.members.insert(m);
            for (auto &p : pending) g.pendingRequests.insert(p);
            state.groups[groupId] = g;
        } else {
            for (auto &m : members) it->second.members.insert(m);
            for (auto &p : pending) it->second.pendingRequests.insert(p);
        }
    }

    in >> tag >> count;
    in.ignore();
    for (long long i = 0; i < count; i++) {
        string fileKey, groupId, filename, fileSHA, ownerId, pieceLine;
        long long fileSize = 0, totalChunks = 0;
        size_t seederCount = 0;

        getline(in, fileKey);
        getline(in, groupId);
        getline(in, filename);
        getline(in, fileSHA);
        getline(in, ownerId);
        in >> fileSize >> totalChunks;
        in.ignore();
        getline(in, pieceLine);
        in >> seederCount;
        in.ignore();

        vector<string> chunkHashes;
        stringstream pss(pieceLine);
        string piece;
        while (getline(pss, piece, ',')) if (!piece.empty()) chunkHashes.push_back(piece);

        vector<SeederInfo> seeders;
        for (size_t s = 0; s < seederCount; s++) {
            string line2;
            getline(in, line2);
            stringstream lss(line2);
            SeederInfo si;
            string bf;
            lss >> si.userId >> si.ip >> si.port >> bf;
            si.haveChunk = stringToBitfield(bf);
            seeders.push_back(si);
        }

        auto it = state.files.find(fileKey);
        if (it == state.files.end()) {
            FileMetaData f;
            f.fileKey = fileKey;
            f.groupId = groupId;
            f.filename = filename;
            f.fileSHA = fileSHA;
            f.ownerId = ownerId;
            f.fileSize = fileSize;
            f.totalChunks = totalChunks;
            f.chunkHashes = chunkHashes;
            f.seeders = seeders;
            state.files[fileKey] = f;
        } else {
            for (auto &incoming : seeders) {
                bool found = false;
                for (auto &local : it->second.seeders) {
                    if (local.userId == incoming.userId) {
                        found = true;
                        if (local.haveChunk.size() < incoming.haveChunk.size())
                            local.haveChunk.resize(incoming.haveChunk.size(), false);
                        for (size_t c = 0; c < incoming.haveChunk.size(); c++)
                            if (incoming.haveChunk[c]) local.haveChunk[c] = true;
                        break;
                    }
                }
                if (!found) it->second.seeders.push_back(incoming);
            }
        }
    }
}

string createUser(const string &userId, const string &password, bool fromSync) {
    string res;
    {
        lock_guard<mutex> lock(dataLock);
        if (state.users.find(userId) != state.users.end()) {
            res = "ERROR: user_id '" + userId + "' already exists";
            if (fromSync) return res;
        } else {
            UserInfo u;
            u.userId = userId;
            u.passwordHash = hashPassword(password);
            state.users[userId] = u;
            res = "OK: user '" + userId + "' registered successfully";
        }
    }
    if (!fromSync) forwardToPeer("sync_register " + userId + " " + password);
    return res;
}

string loginUser(const string &userId, const string &password, const string &ip, int port, bool fromSync) {
    {
        lock_guard<mutex> lock(dataLock);
        auto it = state.users.find(userId);
        if (it == state.users.end()) {
            if (!fromSync) return "ERROR: user '" + userId + "' is not registered";

            UserInfo u;
            u.userId = userId;
            u.passwordHash = hashPassword(password);
            state.users[userId] = u;
            it = state.users.find(userId);
        } else if (!fromSync && it->second.passwordHash != hashPassword(password)) {
            return "ERROR: invalid password";
        }

        it->second.loggedIn = true;
        it->second.currentIp = ip;
        it->second.currentPort = port;

        for (auto &fkv : state.files) {
            for (auto &s : fkv.second.seeders) {
                if (s.userId == userId) {
                    s.ip = ip;
                    s.port = port;
                }
            }
        }
    }
    if (!fromSync) forwardToPeer("sync_login " + userId + " " + password + " " + ip + " " + to_string(port));
    return "OK: '" + userId + "' logged in successfully";
}

string logoutUser(string &sessionUser, bool fromSync) {
    string userId = sessionUser;
    if (!fromSync && userId.empty()) return "ERROR: no active session";
    {
        lock_guard<mutex> lock(dataLock);
        auto it = state.users.find(userId);
        if (it == state.users.end()) return fromSync ? "" : "ERROR: user not registered";
        it->second.loggedIn = false;

    }
    if (!fromSync) forwardToPeer("sync_logout " + userId);
    sessionUser.clear();
    return "OK: '" + userId + "' logged out";
}

string createGroup(const string &userId, const string &groupId, bool fromSync) {
    {
        lock_guard<mutex> lock(dataLock);
        if (!fromSync) {
            auto uit = state.users.find(userId);
            if (uit == state.users.end() || !uit->second.loggedIn) return "ERROR: login required";
        }
        if (state.groups.find(groupId) != state.groups.end()) {
            if (fromSync) return "";
            return "ERROR: group '" + groupId + "' already exists";
        }
        GroupInfo g;
        g.groupId = groupId;
        g.owner = userId;
        g.members.insert(userId);
        state.groups[groupId] = g;
    }
    if (!fromSync) forwardToPeer("sync_group_create " + groupId + " " + userId);
    return "OK: group '" + groupId + "' created";
}

string joinGroup(const string &userId, const string &groupId, bool fromSync) {
    {
        lock_guard<mutex> lock(dataLock);
        if (!fromSync) {
            auto uit = state.users.find(userId);
            if (uit == state.users.end() || !uit->second.loggedIn) return "ERROR: login required";
        }
        auto git = state.groups.find(groupId);
        if (git == state.groups.end()) return fromSync ? "" : "ERROR: group '" + groupId + "' does not exist";
        if (git->second.members.count(userId)) return fromSync ? "" : "ERROR: already a member";
        if (git->second.pendingRequests.count(userId)) return fromSync ? "" : "ERROR: request already pending";
        git->second.pendingRequests.insert(userId);
    }
    if (!fromSync) forwardToPeer("sync_group_join " + groupId + " " + userId);
    return "OK: join request sent for group '" + groupId + "'";
}

string leaveGroup(const string &userId, const string &groupId, bool fromSync) {
    string res;
    {
        lock_guard<mutex> lock(dataLock);
        if (!fromSync) {
            auto uit = state.users.find(userId);
            if (uit == state.users.end() || !uit->second.loggedIn) return "ERROR: login required";
        }
        auto git = state.groups.find(groupId);
        if (git == state.groups.end()) return fromSync ? "" : "ERROR: group '" + groupId + "' does not exist";
        if (!git->second.members.count(userId)) return fromSync ? "" : "ERROR: not a member of group '" + groupId + "'";

        if (git->second.members.size() == 1) {
            state.groups.erase(groupId);
            res = "OK: group '" + groupId + "' deleted (last member left)";
        } else {
            git->second.members.erase(userId);
            if (git->second.owner == userId) git->second.owner = *git->second.members.begin();
            res = "OK: left group '" + groupId + "'";
        }
    }
    if (!fromSync) forwardToPeer("sync_group_leave " + groupId + " " + userId);
    return res;
}

string listGroups() {
    lock_guard<mutex> lock(dataLock);
    if (state.groups.empty()) return "No groups available";
    string res = "Available groups:";
    for (auto &kv : state.groups) res += "\n  " + kv.first;
    return res;
}

string listRequests(const string &userId, const string &groupId) {
    lock_guard<mutex> lock(dataLock);
    auto uit = state.users.find(userId);
    if (uit == state.users.end() || !uit->second.loggedIn) return "ERROR: login required";
    auto git = state.groups.find(groupId);
    if (git == state.groups.end()) return "ERROR: group '" + groupId + "' does not exist";
    if (git->second.owner != userId) return "ERROR: only the owner can view join requests";
    if (git->second.pendingRequests.empty()) return "No pending requests";
    string res = "Pending requests:";
    for (auto &u : git->second.pendingRequests) res += "\n  " + u;
    return res;
}

string acceptRequest(const string &userId, const string &groupId, const string &reqUserId, bool fromSync) {
    {
        lock_guard<mutex> lock(dataLock);
        if (!fromSync) {
            auto uit = state.users.find(userId);
            if (uit == state.users.end() || !uit->second.loggedIn) return "ERROR: login required";
        }
        auto git = state.groups.find(groupId);
        if (git == state.groups.end()) return fromSync ? "" : "ERROR: group '" + groupId + "' does not exist";
        if (!fromSync && git->second.owner != userId) return "ERROR: only the owner can accept requests";
        if (!git->second.pendingRequests.count(reqUserId)) {
            if (fromSync) { git->second.members.insert(reqUserId); return ""; }
            return "ERROR: no pending request from '" + reqUserId + "'";
        }
        git->second.pendingRequests.erase(reqUserId);
        git->second.members.insert(reqUserId);
    }
    if (!fromSync) forwardToPeer("sync_accept_request " + groupId + " " + reqUserId);
    return "OK: '" + reqUserId + "' added to group '" + groupId + "'";
}

bool hashFile(const string &filePath, long long &fileSize, long long &totalChunks,
              string &fileSHA, vector<string> &chunkHashes) {
    int fd = open(filePath.c_str(), O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }

    fileSize = st.st_size;
    totalChunks = (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    if (totalChunks == 0) totalChunks = 1;

    SHA_CTX fullCtx;
    SHA1_Init(&fullCtx);
    vector<char> buffer(CHUNK_SIZE);

    for (long long i = 0; i < totalChunks; i++) {
        ssize_t bytesRead = read(fd, buffer.data(), CHUNK_SIZE);
        if (bytesRead < 0) { close(fd); return false; }
        unsigned char pHash[SHA_DIGEST_LENGTH];
        SHA1((unsigned char *)buffer.data(), bytesRead, pHash);
        chunkHashes.push_back(sha1Hex(pHash));
        SHA1_Update(&fullCtx, buffer.data(), bytesRead);
    }

    unsigned char fullHash[SHA_DIGEST_LENGTH];
    SHA1_Final(fullHash, &fullCtx);
    fileSHA = sha1Hex(fullHash);
    close(fd);
    return true;
}

void insertOrAugmentFile(const FileMetaData &incoming, const SeederInfo &seeder) {
    auto it = state.files.find(incoming.fileKey);
    if (it == state.files.end()) {
        FileMetaData meta = incoming;
        meta.seeders.clear();
        meta.seeders.push_back(seeder);
        state.files[incoming.fileKey] = meta;
    } else {
        bool found = false;
        for (auto &s : it->second.seeders) {
            if (s.userId == seeder.userId) {
                found = true;
                if (s.haveChunk.size() < seeder.haveChunk.size()) s.haveChunk.resize(seeder.haveChunk.size(), false);
                for (size_t c = 0; c < seeder.haveChunk.size(); c++) if (seeder.haveChunk[c]) s.haveChunk[c] = true;
                break;
            }
        }
        if (!found) it->second.seeders.push_back(seeder);
    }
}

string uploadFile(const string &userId, const string &groupId, const string &filePath) {
    size_t pos = filePath.find_last_of("/\\");
    string filename = (pos != string::npos) ? filePath.substr(pos + 1) : filePath;
    string fileKey = groupId + "_" + filename;

    string ip;
    int port;
    string existingOwner;
    long long fileSize = 0, totalChunks = 0;
    string fileSHA;
    vector<string> chunkHashes;
    bool needsHash = true;

    {
        lock_guard<mutex> lock(dataLock);
        auto uit = state.users.find(userId);
        if (uit == state.users.end() || !uit->second.loggedIn) return "ERROR: login required";
        auto git = state.groups.find(groupId);
        if (git == state.groups.end()) return "ERROR: group '" + groupId + "' does not exist";
        if (!git->second.members.count(userId)) return "ERROR: not a member of group '" + groupId + "'";

        ip = uit->second.currentIp;
        port = uit->second.currentPort;

        auto fit = state.files.find(fileKey);
        if (fit != state.files.end()) {
            needsHash = false;
            existingOwner = fit->second.ownerId;
            fileSize = fit->second.fileSize;
            totalChunks = fit->second.totalChunks;
            fileSHA = fit->second.fileSHA;
            chunkHashes = fit->second.chunkHashes;
        }
    }

    if (needsHash) {
        if (!hashFile(filePath, fileSize, totalChunks, fileSHA, chunkHashes)) {
            return "ERROR: could not open/read file at '" + filePath + "'";
        }
        existingOwner = userId;
    }

    FileMetaData meta;
    meta.fileKey = fileKey;
    meta.groupId = groupId;
    meta.filename = filename;
    meta.fileSHA = fileSHA;
    meta.ownerId = existingOwner;
    meta.fileSize = fileSize;
    meta.totalChunks = totalChunks;
    meta.chunkHashes = chunkHashes;

    SeederInfo seeder;
    seeder.userId = userId;
    seeder.ip = ip;
    seeder.port = port;
    seeder.haveChunk = vector<bool>(totalChunks, true);

    {
        lock_guard<mutex> lock(dataLock);
        insertOrAugmentFile(meta, seeder);
    }

    vector<string> msg = {"sync_upload_file", fileKey, groupId, filename, fileSHA, existingOwner,
                           to_string(fileSize), to_string(totalChunks), join(chunkHashes, ','),
                           userId, ip, to_string(port)};
    forwardToPeer(join(msg, ' '));

    return needsHash
        ? "OK: uploaded '" + filename + "' (" + to_string(fileSize) + " bytes, " + to_string(totalChunks) + " chunks)"
        : "OK: file already shared in group; you were added as a seeder";
}

void applySyncUploadFile(const vector<string> &fields) {

    if (fields.size() != 12) return;
    FileMetaData meta;
    meta.fileKey = fields[1];
    meta.groupId = fields[2];
    meta.filename = fields[3];
    meta.fileSHA = fields[4];
    meta.ownerId = fields[5];

    if (!tryParseLongLong(fields[6], meta.fileSize) || !tryParseLongLong(fields[7], meta.totalChunks)) return;
    stringstream pss(fields[8]);
    string piece;
    while (getline(pss, piece, ',')) if (!piece.empty()) meta.chunkHashes.push_back(piece);

    SeederInfo seeder;
    seeder.userId = fields[9];
    seeder.ip = fields[10];
    if (!tryParseInt(fields[11], seeder.port)) return;
    seeder.haveChunk = vector<bool>(meta.totalChunks, true);

    lock_guard<mutex> lock(dataLock);
    insertOrAugmentFile(meta, seeder);
}

string listFiles(const string &userId, const string &groupId) {
    lock_guard<mutex> lock(dataLock);
    auto uit = state.users.find(userId);
    if (uit == state.users.end() || !uit->second.loggedIn) return "ERROR: login required";
    if (state.groups.find(groupId) == state.groups.end()) return "ERROR: group '" + groupId + "' does not exist";
    if (!state.groups[groupId].members.count(userId)) return "ERROR: not a member of group '" + groupId + "'";

    string res;
    for (auto &kv : state.files) {
        if (kv.second.groupId == groupId) {
            res += kv.second.filename + "  (size=" + to_string(kv.second.fileSize) +
                   "B, chunks=" + to_string(kv.second.totalChunks) + ")\n";
        }
    }
    if (res.empty()) return "No files available in group '" + groupId + "'";
    return "Files in group '" + groupId + "':\n" + res;
}

string getFileMetadata(const string &userId, const string &groupId, const string &filename) {
    lock_guard<mutex> lock(dataLock);

    auto uit = state.users.find(userId);
    if (uit == state.users.end() || !uit->second.loggedIn) return "ERROR:login required";
    auto git = state.groups.find(groupId);
    if (git == state.groups.end()) return "ERROR:group does not exist";
    if (!git->second.members.count(userId)) return "ERROR:not a member of this group";

    string fileKey = groupId + "_" + filename;
    auto it = state.files.find(fileKey);
    if (it == state.files.end()) return "ERROR:file not found";
    auto &meta = it->second;

    string peerInfo;
    int validPeers = 0;
    for (auto &s : meta.seeders) {
        auto uit = state.users.find(s.userId);
        if (uit == state.users.end() || !uit->second.loggedIn) continue;
        if (validPeers > 0) peerInfo += "|";
        peerInfo += s.ip + ":" + to_string(s.port) + ":" + bitfieldToString(s.haveChunk);
        validPeers++;
    }
    if (validPeers == 0) return "ERROR:no active seeders";

    string chunkHashesStr = join(meta.chunkHashes, ',');
    return to_string(meta.fileSize) + " " + to_string(meta.totalChunks) + " " +
           peerInfo + " " + meta.fileSHA + " " + chunkHashesStr;
}

string updatePiece(const string &userId, const string &fileKey, int chunkIndex, bool fromSync,
                    const string &syncIp = "", int syncPort = -1) {
    lock_guard<mutex> lock(dataLock);
    auto it = state.files.find(fileKey);
    if (it == state.files.end()) return "ERROR:file not found";
    if (!fromSync) {
        auto uit = state.users.find(userId);
        if (uit == state.users.end() || !uit->second.loggedIn) return "ERROR:user not logged in";
    }
    if (chunkIndex < 0 || chunkIndex >= it->second.totalChunks) return "ERROR:invalid chunk index";

    auto &meta = it->second;
    bool found = false;
    for (auto &s : meta.seeders) {
        if (s.userId == userId) {
            if ((long long)s.haveChunk.size() != meta.totalChunks) s.haveChunk.resize(meta.totalChunks, false);
            s.haveChunk[chunkIndex] = true;
            found = true;
            break;
        }
    }
    string ip = fromSync ? syncIp : state.users[userId].currentIp;
    int port = fromSync ? syncPort : state.users[userId].currentPort;
    if (!found) {
        SeederInfo si;
        si.userId = userId;
        si.ip = ip;
        si.port = port;
        si.haveChunk = vector<bool>(meta.totalChunks, false);
        si.haveChunk[chunkIndex] = true;
        meta.seeders.push_back(si);
    }

    if (!fromSync) {
        forwardToPeer("sync_update_piece " + fileKey + " " + to_string(chunkIndex) + " " +
                       userId + " " + ip + " " + to_string(port));
    }
    return "OK:piece updated";
}

string stopSharing(const string &userId, const string &groupId, const string &filename, bool fromSync) {
    string fileKey = groupId + "_" + filename;
    {
        lock_guard<mutex> lock(dataLock);
        auto it = state.files.find(fileKey);
        if (it == state.files.end()) return "ERROR:file not found";
        bool removed = false;
        auto &seeders = it->second.seeders;
        for (auto sit = seeders.begin(); sit != seeders.end(); ++sit) {
            if (sit->userId == userId) {
                seeders.erase(sit);
                removed = true;
                break;
            }
        }
        if (!removed) return "ERROR:not currently sharing this file";
    }
    if (!fromSync) forwardToPeer("sync_stop_share " + groupId + " " + filename + " " + userId);
    return "OK:stopped sharing";
}

string processCommand(const string &command, string &sessionUser) {
    vector<string> tokens = tokenize(command);
    if (tokens.empty()) return "ERROR: empty command";
    size_t count = tokens.size();

    if (tokens[0] == "create_user") {
        if (count != 3) return "ERROR: usage: create_user <user_id> <password>";
        return createUser(tokens[1], tokens[2], false);
    }
    if (tokens[0] == "login") {
        if (count != 5) return "ERROR: usage: login <user_id> <password>";
        int port;
        if (!tryParseInt(tokens[4], port)) return "ERROR: invalid port";
        string res = loginUser(tokens[1], tokens[2], tokens[3], port, false);
        if (res.rfind("OK", 0) == 0) sessionUser = tokens[1];
        return res;
    }
    if (tokens[0] == "logout") {
        if (count != 1) return "ERROR: usage: logout";
        return logoutUser(sessionUser, false);
    }
    if (tokens[0] == "create_group") {
        if (count != 2) return "ERROR: usage: create_group <group_id>";
        return createGroup(sessionUser, tokens[1], false);
    }
    if (tokens[0] == "join_group") {
        if (count != 2) return "ERROR: usage: join_group <group_id>";
        return joinGroup(sessionUser, tokens[1], false);
    }
    if (tokens[0] == "leave_group") {
        if (count != 2) return "ERROR: usage: leave_group <group_id>";
        return leaveGroup(sessionUser, tokens[1], false);
    }
    if (tokens[0] == "list_groups") {
        if (count != 1) return "ERROR: usage: list_groups";
        return listGroups();
    }
    if (tokens[0] == "list_requests") {
        if (count != 2) return "ERROR: usage: list_requests <group_id>";
        return listRequests(sessionUser, tokens[1]);
    }
    if (tokens[0] == "accept_request") {
        if (count != 3) return "ERROR: usage: accept_request <group_id> <user_id>";
        return acceptRequest(sessionUser, tokens[1], tokens[2], false);
    }
    if (tokens[0] == "upload_file") {
        if (count != 3) return "ERROR: usage: upload_file <group_id> <file_path>";
        return uploadFile(sessionUser, tokens[1], tokens[2]);
    }
    if (tokens[0] == "list_files") {
        if (count != 2) return "ERROR: usage: list_files <group_id>";
        return listFiles(sessionUser, tokens[1]);
    }
    if (tokens[0] == "get_file_metadata") {
        if (count != 3) return "ERROR: usage: get_file_metadata <group_id> <filename>";
        return getFileMetadata(sessionUser, tokens[1], tokens[2]);
    }
    if (tokens[0] == "update_piece") {
        if (count != 3) return "ERROR: usage: update_piece <file_key> <chunk_index>";
        int chunkIndex;
        if (!tryParseInt(tokens[2], chunkIndex)) return "ERROR: invalid chunk index";
        return updatePiece(sessionUser, tokens[1], chunkIndex, false);
    }
    if (tokens[0] == "stop_share") {
        if (count != 3) return "ERROR: usage: stop_share <group_id> <filename>";
        return stopSharing(sessionUser, tokens[1], tokens[2], false);
    }

    return "ERROR: invalid command";
}

void applySyncCommand(const vector<string> &fields) {
    const string &op = fields[0];
    int parsedInt1, parsedInt2;
    if (op == "sync_register" && fields.size() == 3) {
        createUser(fields[1], fields[2], true);
    } else if (op == "sync_login" && fields.size() == 5) {
        if (tryParseInt(fields[4], parsedInt1)) loginUser(fields[1], fields[2], fields[3], parsedInt1, true);
    } else if (op == "sync_logout" && fields.size() == 2) {
        string u = fields[1];
        logoutUser(u, true);
    } else if (op == "sync_group_create" && fields.size() == 3) {
        createGroup(fields[2], fields[1], true);
    } else if (op == "sync_group_join" && fields.size() == 3) {
        joinGroup(fields[2], fields[1], true);
    } else if (op == "sync_group_leave" && fields.size() == 3) {
        leaveGroup(fields[2], fields[1], true);
    } else if (op == "sync_accept_request" && fields.size() == 3) {
        acceptRequest("", fields[1], fields[2], true);
    } else if (op == "sync_upload_file") {
        applySyncUploadFile(fields);
    } else if (op == "sync_update_piece" && fields.size() == 6) {
        if (tryParseInt(fields[2], parsedInt1) && tryParseInt(fields[5], parsedInt2)) {
            updatePiece(fields[3], fields[1], parsedInt1, true, fields[4], parsedInt2);
        }
    } else if (op == "sync_stop_share" && fields.size() == 4) {
        stopSharing(fields[3], fields[1], fields[2], true);
    }

}

void handleConnection(int sock) {
    string sessionUser;

    while (true) {
        string command;
        if (!recvFramed(sock, command)) break;
        if (command.empty()) continue;

        vector<string> tokens = tokenize(command);
        if (tokens.empty()) continue;

        if (tokens[0] == "SYNC_REQUEST_SNAPSHOT") {
            sendFramed(sock, buildSnapshot());
            continue;
        }
        if (tokens[0].rfind("sync_", 0) == 0) {
            applySyncCommand(tokens);
            continue;
        }

        string response = processCommand(command, sessionUser);
        if (!sendFramed(sock, response)) break;
    }

    close(sock);
}

void peerConnectionManager() {
    while (true) {
        if (!peerConnected) {
            int s = connectWithTimeout(peerIp, peerPort, 2000);
            if (s >= 0) {
                {
                    lock_guard<mutex> lock(peerLock);
                    peerSock = s;
                    peerConnected = true;
                }
                cout << "Connected to the peer tracker at " << peerIp << ":" << peerPort << endl;

                if (sendFramed(s, "SYNC_REQUEST_SNAPSHOT")) {
                    string snap;
                    if (recvFramed(s, snap)) {
                        mergeSnapshot(snap);
                        cout << "Caught up on whatever changed while we were apart." << endl;
                    }
                }
            }
        }
        this_thread::sleep_for(chrono::seconds(2));

        if (peerConnected) {
            lock_guard<mutex> lock(peerLock);
            if (peerSock >= 0 && !sendFramed(peerSock, "sync_ping")) {
                close(peerSock);
                peerSock = -1;
                peerConnected = false;
                cout << "Lost the connection to the peer tracker, will keep retrying." << endl;
            }
        }
    }
}

void consoleThread(int listenFd) {
    string line;
    while (getline(cin, line)) {
        if (line == "quit") {
            cout << "Shutting down..." << endl;
            close(listenFd);
            _exit(0);
        }
    }
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    if (argc < 3) {
        cout << "usage: ./tracker <tracker_info_file> <tracker_no: 1|2>" << endl;
        return 1;
    }

    int selfIdx = atoi(argv[2]);
    if (selfIdx != 1 && selfIdx != 2) {
        cout << "tracker_no must be 1 or 2" << endl;
        return 1;
    }

    FILE *file = fopen(argv[1], "r");
    if (!file) {
        cout << "Error: could not open tracker info file '" << argv[1] << "'" << endl;
        return 1;
    }
    vector<string> lines;
    {
        char lineBuf[512];
        while (fgets(lineBuf, sizeof(lineBuf), file)) {
            string l(lineBuf);
            while (!l.empty() && (l.back() == '\n' || l.back() == '\r')) l.pop_back();
            if (!l.empty()) lines.push_back(l);
        }
    }
    fclose(file);

    if (lines.size() < 2) {
        cout << "Error: tracker info file must contain two ip:port lines" << endl;
        return 1;
    }

    auto splitAddr = [](const string &s, string &ip, int &port) -> bool {
        size_t c = s.find(':');
        if (c == string::npos) return false;
        ip = s.substr(0, c);
        return tryParseInt(s.substr(c + 1), port);
    };

    bool addrsOk;
    if (selfIdx == 1) {
        addrsOk = splitAddr(lines[0], myIp, myPort) && splitAddr(lines[1], peerIp, peerPort);
    } else {
        addrsOk = splitAddr(lines[1], myIp, myPort) && splitAddr(lines[0], peerIp, peerPort);
    }
    if (!addrsOk) {
        cout << "Error: tracker info file lines must look like ip:port" << endl;
        return 1;
    }

    int listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(myPort);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listenFd);
        return 1;
    }
    if (listen(listenFd, 16) < 0) {
        perror("listen");
        close(listenFd);
        return 1;
    }

    cout << "Tracker " << selfIdx << " listening on " << myIp << ":" << myPort
         << " (peer tracker is at " << peerIp << ":" << peerPort << ")" << endl;
    cout << "Type 'quit' to shut down this tracker." << endl;

    thread(peerConnectionManager).detach();
    thread(consoleThread, listenFd).detach();

    while (true) {
        struct sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int clientSock = accept(listenFd, (struct sockaddr *)&clientAddr, &len);
        if (clientSock < 0) {
            if (errno == EBADF) break;
            continue;
        }

        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, sizeof(ipStr));
        cout << "New connection from " << ipStr << ":" << ntohs(clientAddr.sin_port) << endl;

        thread(handleConnection, clientSock).detach();
    }

    return 0;
}

#include <iostream>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <sstream>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <algorithm>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <limits.h>
#include <csignal>
#include <cmath>
#include <cctype>
#include "common.h"

using namespace std;

static const long long CHUNK_SIZE = 512LL * 1024LL;
static const int MAX_CONCURRENT_DOWNLOADS = 4;

// Size of the vector we turn a file's description into. The vector database
// cluster this talks to must be configured with the same dimension
// (dimension: 32 in its shard_config.txt), or every insert is rejected.
static const int EMBED_DIM = 32;

class ChunkDownloadPool{
private:
    vector<thread> workers;
    queue<function<void()>> tasks;
    mutex qLock;
    condition_variable cv;
    atomic<bool> stopFlag;
    atomic<int> busy;

public:
    ChunkDownloadPool(size_t threadCount) : stopFlag(false), busy(0){
        for(size_t i = 0; i < threadCount; i++){
            workers.emplace_back([this]{
                while(true){
                    function<void()> task;
                   {
                        unique_lock<mutex> lock(qLock);
                        cv.wait(lock, [this]{ return stopFlag || !tasks.empty(); });
                        if (stopFlag && tasks.empty()) return;
                        task = move(tasks.front());
                        tasks.pop();
                    }
                    busy++;
                    task();
                    busy--;
                }
            });
        }
    }

    void enqueue(function<void()> task){
       {
            lock_guard<mutex> lock(qLock);
            tasks.push(move(task));
        }
        cv.notify_one();
    }

    int activeCount(){ return busy.load(); }

    int queuedCount(){
        lock_guard<mutex> lock(qLock);
        return (int)tasks.size();
    }

    ~ChunkDownloadPool(){
        stopFlag = true;
        cv.notify_all();
        for(thread &w : workers) if (w.joinable()) w.join();
    }
};

struct DownloadStatus{
    string groupId;
    string filename;
    string fileKey;
    long long totalChunks = 0;
    vector<bool> have;
    vector<bool> busy;
    bool completed = false;
    mutex lock;
};

struct SeedInfo{
    string filePath;
    long long totalChunks;
};

struct PeerInfo{
    string ip;
    int port;
    vector<bool> availability;
};

unordered_map<string, DownloadStatus> downloads;
unordered_map<string, SeedInfo> sharedFiles;
mutex downloadsLock;
mutex sharedLock;

int trackerSock = -1;

int bgSock = -1;
mutex bgLock;

string primaryIp, secondaryIp;
int primaryPort = -1, secondaryPort = -1;
string clientIp;
int clientPort = 0;

string myUser, myPass;
atomic<bool> loggedIn(false);

// Addresses of the vector database peers (read from the optional
// vectordb_info.txt). Any peer can act as coordinator, so we just try them
// in order. Empty means the vector database wasn't configured, and the
// description/search features stay switched off.
vector<string> vdbIps;
vector<int> vdbPorts;

string sha1ToHex(unsigned char *hash){
    char buf[41];
    for(int i = 0; i < 20; i++) sprintf(buf + (i * 2), "%02x", hash[i]);
    buf[40] = '\0';
    return string(buf);
}

bool verifyChunk(const char *data, size_t size, const string &expectedHash){
    unsigned char hash[20];
    SHA1((const unsigned char *)data, size, hash);
    return sha1ToHex(hash) == expectedHash;
}

vector<string> tokenize(const string &str, char delim = ' '){
    vector<string> tokens;
    stringstream ss(str);
    string token;
    while(getline(ss, token, delim)) 
        if (!token.empty()) tokens.push_back(token);
    return tokens;
}

int connectToEitherTracker(){
    int sock = connectWithTimeout(primaryIp, primaryPort, 3000);
    if (sock >= 0) return sock;
    return connectWithTimeout(secondaryIp, secondaryPort, 3000);
}

string sendToTracker(const string &cmd){
    for(int attempt = 0; attempt < 2; attempt++){
        if (trackerSock < 0){
            trackerSock = connectToEitherTracker();
            if (trackerSock < 0) return "ERROR: could not reach any tracker";
            cout << "Reconnected to the tracker." << endl;
        }
        if (sendFramed(trackerSock, cmd)){
            string resp;
            if (recvFramed(trackerSock, resp)) return resp;
        }
        close(trackerSock);
        trackerSock = -1;
    }
    return "ERROR: could not reach any tracker";
}

string sendBgLocked(const string &cmd){
    for(int attempt = 0; attempt < 2; attempt++){
        if (bgSock < 0){
            bgSock = connectToEitherTracker();
            if (bgSock < 0) return "ERROR: could not reach any tracker";
            if (loggedIn.load()){
                string loginCmd = "login " + myUser + " " + myPass + " " +
                                   clientIp + " " + to_string(clientPort);
                string resp;
                sendFramed(bgSock, loginCmd);
                recvFramed(bgSock, resp);
            }
        }
        if (sendFramed(bgSock, cmd)){
            string resp;
            if (recvFramed(bgSock, resp)) return resp;
        }
        close(bgSock);
        bgSock = -1;
    }
    return "ERROR: could not reach any tracker";
}

string sendBg(const string &cmd){
    lock_guard<mutex> lock(bgLock);
    return sendBgLocked(cmd);
}

// ---------------------------------------------------------------------
// Vector database integration: turn a file's description into a vector,
// store it in the vector database when the file is uploaded, and search
// those vectors later to find files by description instead of exact name.
// Uses the same framing/connect helpers from common.h that the tracker and
// peer connections use.
// ---------------------------------------------------------------------

// Turns free text into a fixed-size vector by hashing each word into one of
// EMBED_DIM buckets and counting it (a hashed bag of words), then scaling the
// result to unit length so a long description doesn't automatically look
// "further away" than a short one. No trained model and no external library -
// two descriptions sharing words end up close together, which is what the
// similarity search needs.
vector<float> embedText(const string &text){
    vector<float> vec(EMBED_DIM, 0.0f);

    stringstream ss(text);
    string word;
    while(ss >> word){
        string lowered;
        for(char c : word){
            if (isalnum((unsigned char)c)) lowered += (char)tolower((unsigned char)c);
        }
        if (lowered.empty()) continue;

        uint32_t hash = 2166136261u;
        for(unsigned char c : lowered){
            hash ^= c;
            hash *= 16777619u;
        }
        vec[hash % EMBED_DIM] += 1.0f;
    }

    float sumOfSquares = 0.0f;
    for(float v : vec) sumOfSquares += v * v;
    float length = sqrt(sumOfSquares);
    if (length > 0.0f){
        for(float &v : vec) v /= length;
    }
    return vec;
}

string vectorToCsv(const vector<float> &vec){
    string out;
    for(size_t i = 0; i < vec.size(); i++){
        if (i) out += ",";
        out += to_string(vec[i]);
    }
    return out;
}

// Sends one request to whichever vector database peer answers first. Any peer
// can coordinate, so an unreachable one just means we try the next.
bool sendToVectorDb(const string &request, string &response){
    for(size_t i = 0; i < vdbIps.size(); i++){
        int sock = connectWithTimeout(vdbIps[i], vdbPorts[i], 3000);
        if (sock < 0) continue;
        bool ok = sendFramed(sock, request) && recvFramed(sock, response);
        close(sock);
        if (ok) return true;
    }
    return false;
}

// Stores a file's description so it can be found by similarity later. The id
// is the same groupId_filename key the tracker and client already agree on,
// so a search hit can be traced straight back to a real shared file.
void indexFileDescription(const string &fileKey, const string &description){
    if (vdbIps.empty()) return;

    vector<float> vec = embedText(description);
    string request = "COORDINATOR_INSERT " + fileKey + " " + to_string(vec.size()) + " " +
                      vectorToCsv(vec) + " " + description;

    string response;
    if (!sendToVectorDb(request, response)){
        cout << "Saved the file, but couldn't reach the vector database to index its description." << endl;
        return;
    }
    if (response.rfind("ERROR", 0) == 0 || response.find("replicas_ok=0") != string::npos){
        cout << "Saved the file, but the vector database rejected its description: " << response << endl;
        return;
    }
    cout << "Description indexed for search." << endl;
}

// Finds files whose description is closest to the given text, then keeps only
// the ones belonging to this group (the id is groupId_filename, so a group's
// files all share that prefix).
void searchFilesByDescription(const string &groupId, const string &queryText){
    if (vdbIps.empty()){
        cout << "Search needs the vector database. Start it and pass vectordb_info.txt as the third argument." << endl;
        return;
    }

    vector<float> vec = embedText(queryText);
    string request = "COORDINATOR_QUERY 10 50 " + to_string(vec.size()) + " " + vectorToCsv(vec);

    string response;
    if (!sendToVectorDb(request, response)){
        cout << "Couldn't reach the vector database." << endl;
        return;
    }
    if (response.rfind("ERROR", 0) == 0){
        cout << "Search failed: " << response << endl;
        return;
    }

    // Response: "<shardsTotal> <shardsAnswered> <latencyMs> <count> [id:dist:meta|...]"
    vector<string> head;
    stringstream hs(response);
    string tok;
    for(int i = 0; i < 4 && (hs >> tok); i++) head.push_back(tok);
    if (head.size() < 4){
        cout << "Got an unexpected answer from the vector database." << endl;
        return;
    }

    size_t entriesStart = response.find(' ');
    for(int i = 0; i < 3 && entriesStart != string::npos; i++){
        entriesStart = response.find(' ', entriesStart + 1);
    }

    string prefix = groupId + "_";
    int shown = 0;
    if (entriesStart != string::npos && entriesStart + 1 < response.size()){
        stringstream entryStream(response.substr(entriesStart + 1));
        string entry;
        while(getline(entryStream, entry, '|')){
            if (entry.empty()) continue;
            size_t firstColon = entry.find(':');
            size_t secondColon = entry.find(':', firstColon + 1);
            if (firstColon == string::npos || secondColon == string::npos) continue;

            string id = entry.substr(0, firstColon);
            string distance = entry.substr(firstColon + 1, secondColon - firstColon - 1);
            string description = entry.substr(secondColon + 1);
            if (id.rfind(prefix, 0) != 0) continue; // a different group's file

            shown++;
            cout << " " << shown << ". " << id.substr(prefix.size())
                 << "  (distance " << distance << ")  \"" << description << "\"" << endl;
        }
    }

    if (shown == 0) cout << "No files in this group match that description." << endl;
}

bool parseMetadata(const string &metadata, long long &fileSize, long long &totalChunks,
                    string &fileSHA, vector<string> &chunkHashes, vector<PeerInfo> &peers){
    if (metadata.rfind("ERROR", 0) == 0) return false;

    stringstream ss(metadata);
    string tok;
    vector<string> tokens;
    for(int i = 0; i < 5 && (ss >> tok); i++) tokens.push_back(tok);
    if (tokens.size() < 5) return false;

    if (!tryParseLongLong(tokens[0], fileSize)) return false;
    if (!tryParseLongLong(tokens[1], totalChunks)) return false;

    string peerStr = tokens[2];
    stringstream peerSS(peerStr);
    string peerEntry;
    while(getline(peerSS, peerEntry, '|')){
        if (peerEntry.empty()) continue;
        vector<string> parts = tokenize(peerEntry, ':');
        if (parts.size() < 3) continue;
        PeerInfo peer;
        peer.ip = parts[0];
        if (!tryParseInt(parts[1], peer.port)) continue;
        for(char c : parts[2]) if (c == '0' || c == '1') peer.availability.push_back(c == '1');
        if (!peer.availability.empty()) peers.push_back(peer);
    }

    fileSHA = tokens[3];
    for(auto &s : tokenize(tokens[4], ',')) chunkHashes.push_back(s);

    return fileSize > 0 && totalChunks > 0 && !fileSHA.empty() &&
           (long long)chunkHashes.size() == totalChunks && !peers.empty();
}

void removeSelfFromPeers(vector<PeerInfo> &peers){
    vector<PeerInfo> kept;
    for(auto &peer : peers){
        if (peer.ip == clientIp && peer.port == clientPort) continue;
        kept.push_back(peer);
    }
    peers = kept;
}

bool getChunkFromPeer(const string &peerIp, int peerPort, const string &fileKey,
                       int chunkIndex, vector<char> &out){
    int sock = connectWithTimeout(peerIp, peerPort, 5000);
    if (sock < 0) return false;

    string req = "REQUEST_CHUNK " + fileKey + " " + to_string(chunkIndex);
    if (!sendFramed(sock, req)){ close(sock); return false; }

    string payload;
    bool ok = recvFramed(sock, payload);
    close(sock);
    if (!ok || payload.empty() || payload[0] != '1') return false;

    out.assign(payload.begin() + 1, payload.end());
    return true;
}

int pickRarestChunk(const vector<bool> &have, const vector<bool> &busy,
                     const vector<PeerInfo> &peers, long long totalChunks){
    vector<int> peerCount(totalChunks, 0);
    for(auto &peer : peers){
        for(long long i = 0; i < totalChunks && i < (long long)peer.availability.size(); i++){
            if (!have[i] && !busy[i] && peer.availability[i]) peerCount[i]++;
        }
    }
    int bestChunk = -1, bestCount = INT_MAX;
    for(long long i = 0; i < totalChunks; i++){
        if (!have[i] && !busy[i] && peerCount[i] > 0 && peerCount[i] < bestCount){
            bestCount = peerCount[i];
            bestChunk = (int)i;
        }
    }
    return bestChunk;
}

void downloadFileThread(string groupId, string filename, string destPath){
    string fileKey = groupId + "_" + filename;
    cout << "\nStarting download of " << filename << "..." << endl;

    string metaResp = sendBg("get_file_metadata " + groupId + " " + filename);

    long long fileSize = 0, totalChunks = 0;
    string fileSHA;
    vector<string> chunkHashes;
    vector<PeerInfo> peers;

    if (!parseMetadata(metaResp, fileSize, totalChunks, fileSHA, chunkHashes, peers)){
        cout << "Couldn't get file info: " << metaResp << endl;
        return;
    }
    removeSelfFromPeers(peers);
    if (peers.empty()){
        cout << "No other peers currently have this file." << endl;
        return;
    }

    cout << "It's " << fileSize << " bytes, " << totalChunks << " chunks. Found "
         << peers.size() << " peer(s) who have it." << endl;

    DownloadStatus *statusPtr;
   {
        lock_guard<mutex> lock(downloadsLock);
        DownloadStatus &entry = downloads[fileKey];
        entry.groupId = groupId;
        entry.filename = filename;
        entry.fileKey = fileKey;
        entry.totalChunks = totalChunks;
        entry.have = vector<bool>(totalChunks, false);
        entry.busy = vector<bool>(totalChunks, false);
        entry.completed = false;
        statusPtr = &entry;
    }
    DownloadStatus &status = *statusPtr;

    int fd = open(destPath.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0){ perror("Couldn't create the destination file"); return; }

    if (ftruncate(fd, fileSize) < 0){
        perror("Couldn't allocate space forthe destination file");
        close(fd);
        return;
    }

    ChunkDownloadPool pool(MAX_CONCURRENT_DOWNLOADS);
    atomic<int> doneCount(0);
    atomic<int> failStreak(0);
    mutex peersLock;

    while(true){
        vector<int> toDownload;
       {
            lock_guard<mutex> lock(status.lock);

            bool allDone = true;
            for(bool got : status.have) if (!got){ allDone = false; break; }
            if (allDone){
                status.completed = true;
                break;
            }
            int inFlight = pool.activeCount() + pool.queuedCount();
            int freeSlots = MAX_CONCURRENT_DOWNLOADS - inFlight;
            lock_guard<mutex> plock(peersLock);
            for(int i = 0; i < freeSlots; i++){
                int chunkIndex = pickRarestChunk(status.have, status.busy, peers, status.totalChunks);
                if (chunkIndex == -1) break;
                status.busy[chunkIndex] = true;
                toDownload.push_back(chunkIndex);
            }
        }

        if (toDownload.empty()){
            if (pool.activeCount() == 0 && pool.queuedCount() == 0){
                if (failStreak.load() > 30){
                    cout << "Download stalled - no peer has the pieces we still need." << endl;
                    break;
                }
                sleep(1);
                failStreak++;
            } else{
                usleep(100000);
            }
            continue;
        }

        for(int chunkIndex : toDownload){
            pool.enqueue([&, chunkIndex, fd](){
                vector<PeerInfo> candidatePeers;
               {
                    lock_guard<mutex> plock(peersLock);
                    for(auto &peer : peers){
                        if (chunkIndex < (int)peer.availability.size() && peer.availability[chunkIndex]){
                            candidatePeers.push_back(peer);
                        }
                    }
                }

                bool success = false;
                for(auto &peer : candidatePeers){
                    vector<char> buf;
                    if (!getChunkFromPeer(peer.ip, peer.port, fileKey, chunkIndex, buf)){
                        cout << "Couldn't reach " << peer.ip << ":" << peer.port
                             << " forchunk " << chunkIndex << ", trying someone else." << endl;
                        continue;
                    }
                    if (!verifyChunk(buf.data(), buf.size(), chunkHashes[chunkIndex])){
                        cout << "Chunk " << chunkIndex << " from " << peer.ip << ":" << peer.port
                             << " didn't pass the integrity check, trying another peer." << endl;
                        continue;
                    }

                    off_t offset = (off_t)chunkIndex * CHUNK_SIZE;
                    ssize_t written = pwrite(fd, buf.data(), buf.size(), offset);
                    if (written != (ssize_t)buf.size()) continue;

                    success = true;
                    int done = ++doneCount;
                    int pct = (int)((done * 100) / totalChunks);
                    cout << "Got chunk " << chunkIndex << " from " << peer.ip << ":" << peer.port
                         << " (" << done << "/" << totalChunks << ", " << pct << "%)" << endl;

                   {
                        lock_guard<mutex> lock(sharedLock);
                        sharedFiles[fileKey] = SeedInfo{destPath, totalChunks};
                    }

                    sendBg("update_piece " + fileKey + " " + to_string(chunkIndex));

                   {
                        lock_guard<mutex> lock(status.lock);
                        status.have[chunkIndex] = true;
                    }
                    failStreak = 0;
                    break;
                }

                if (!success){
                    lock_guard<mutex> lock(status.lock);
                    status.busy[chunkIndex] = false;
                    failStreak++;
                }
            });
        }

        if (failStreak.load() > 10){
            cout << "\nHaving trouble finding peers forthe remaining chunks, refreshing the peer list..." << endl;
            string refreshResp = sendBg("get_file_metadata " + groupId + " " + filename);
            long long freshSize, freshTotal;
            string freshSHA;
            vector<string> freshHashes;
            vector<PeerInfo> freshPeers;
            if (parseMetadata(refreshResp, freshSize, freshTotal, freshSHA, freshHashes, freshPeers)){
                removeSelfFromPeers(freshPeers);
                lock_guard<mutex> plock(peersLock);
                peers = freshPeers;
                failStreak = 0;
                cout << "Now know about " << peers.size() << " peer(s)." << endl;
            }
        }

        usleep(50000);
    }

    while(pool.activeCount() > 0 || pool.queuedCount() > 0) usleep(100000);
    close(fd);

    if (status.completed){
        cout << "\nDone! " << filename << " (group " << groupId << ") downloaded successfully." << endl;
    } else{
        cout << "\nDownload of " << filename << " did not finish." << endl;
    }
}

void handlePeerRequest(int sock){
    string request;
    if (!recvFramed(sock, request)){ close(sock); return; }

    auto tokens = tokenize(request);
    if (tokens.size() >= 3 && tokens[0] == "REQUEST_CHUNK"){
        string fileKey = tokens[1];
        int chunkIndex = -1;
        tryParseInt(tokens[2], chunkIndex);

        string filePath;
        long long totalChunks = 0;
        bool have = false;
       {
            lock_guard<mutex> lock(sharedLock);
            auto it = sharedFiles.find(fileKey);
            if (it != sharedFiles.end()){
                filePath = it->second.filePath;
                totalChunks = it->second.totalChunks;
                have = true;
            }
        }

        if (have && chunkIndex >= 0 && chunkIndex < totalChunks){
            int fd = open(filePath.c_str(), O_RDONLY);
            if (fd >= 0){
                vector<char> buf(CHUNK_SIZE);
                ssize_t n = pread(fd, buf.data(), CHUNK_SIZE, (off_t)chunkIndex * CHUNK_SIZE);
                close(fd);
                if (n >= 0){
                    string payload;
                    payload.reserve(n + 1);
                    payload.push_back('1');
                    payload.append(buf.data(), n);
                    sendFramed(sock, payload);
                    close(sock);
                    return;
                }
            }
        }
        sendFramed(sock, "0chunk_not_available");
    } else{
        sendFramed(sock, "0bad_request");
    }
    close(sock);
}

void peerServerThread(int port){
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0){ perror("Couldn't open a socket to serve peers on"); return; }

    int opt = 1;
    setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSock, (struct sockaddr *)&addr, sizeof(addr)) < 0){ perror("Couldn't bind the peer-serving port"); close(serverSock); return; }
    if (listen(serverSock, 16) < 0){ perror("Couldn't listen on the peer-serving port"); close(serverSock); return; }

    cout << "Ready to serve file chunks to other peers on port " << port << endl;

    while(true){
        struct sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int clientSock = accept(serverSock, (struct sockaddr *)&clientAddr, &len);
        if (clientSock >= 0) thread(handlePeerRequest, clientSock).detach();
    }
}

string showDownloads(){
    lock_guard<mutex> lock(downloadsLock);
    if (downloads.empty()) return "No active downloads";

    string result;
    for(auto &entry : downloads){
        DownloadStatus &status = entry.second;

        lock_guard<mutex> entryLock(status.lock);
        if (status.completed){
            result += "Done: " + status.filename + " (group " + status.groupId + ")\n";
            continue;
        }
        int gotCount = 0;
        for(bool got : status.have) if (got) gotCount++;
        int pct = status.totalChunks ? (int)((gotCount * 100) / status.totalChunks) : 0;
        result += status.filename + " (group " + status.groupId + "): " +
                   to_string(gotCount) + "/" + to_string(status.totalChunks) +
                   " chunks, " + to_string(pct) + "% done\n";
    }
    return result;
}

string stopShare(const string &groupId, const string &filename){
    string fileKey = groupId + "_" + filename;
   {
        lock_guard<mutex> lock(sharedLock);
        if (sharedFiles.find(fileKey) == sharedFiles.end()) return "Not currently sharing: " + filename;
    }
    string resp = sendToTracker("stop_share " + groupId + " " + filename);
    if (resp.rfind("OK", 0) == 0){
        lock_guard<mutex> lock(sharedLock);
        sharedFiles.erase(fileKey);
    }
    return resp;
}

int main(int argc, char *argv[]){
    signal(SIGPIPE, SIG_IGN);

    if (argc < 3){
        cout << "usage: ./client <IP>:<PORT> <tracker_info_file> [vectordb_info_file]" << endl;
        return 1;
    }

    auto self = tokenize(argv[1], ':');
    if (self.size() < 2 || !tryParseInt(self[1], clientPort)){
        cout << "Invalid <IP>:<PORT>" << endl;
        return 1;
    }
    clientIp = self[0];

    FILE *file = fopen(argv[2], "r");
    if (!file){ cout << "Error: could not open tracker info file" << endl; return 1; }
    char ch;
    string inputFile;
    while((ch = fgetc(file)) != EOF) inputFile += ch;
    fclose(file);

    auto lines = tokenize(inputFile, '\n');
    if (lines.size() < 2){ cout << "Invalid tracker info file" << endl; return 1; }
    auto primary = tokenize(lines[0], ':');
    auto secondary = tokenize(lines[1], ':');
    if (primary.size() < 2 || secondary.size() < 2 ||
        !tryParseInt(primary[1], primaryPort) || !tryParseInt(secondary[1], secondaryPort)){
        cout << "Invalid tracker info file" << endl;
        return 1;
    }
    primaryIp = primary[0];
    secondaryIp = secondary[0];

    // Optional: addresses of the vector database peers, one ip:port per line.
    // Without this the client works exactly as before, just without
    // description indexing and search_files.
    if (argc >= 4){
        FILE *vdbFile = fopen(argv[3], "r");
        if (!vdbFile){
            cout << "Warning: could not open " << argv[3] << " - search_files will be unavailable." << endl;
        } else {
            string vdbText;
            while((ch = fgetc(vdbFile)) != EOF) vdbText += ch;
            fclose(vdbFile);

            for(auto &line : tokenize(vdbText, '\n')){
                auto parts = tokenize(line, ':');
                int port;
                if (parts.size() < 2 || !tryParseInt(parts[1], port)) continue;
                vdbIps.push_back(parts[0]);
                vdbPorts.push_back(port);
            }
            if (vdbIps.empty()){
                cout << "Warning: no usable ip:port lines in " << argv[3] << " - search_files will be unavailable." << endl;
            }
        }
    }

    cout << "Your address is " << clientIp << ":" << clientPort << endl;

    trackerSock = connectToEitherTracker();
    if (trackerSock < 0){
        cerr << "Couldn't connect to either tracker." << endl;
        return 1;
    }
    cout << "Connected to the tracker." << endl;

    thread(peerServerThread, clientPort).detach();
    sleep(1);

    string command;
    while(true){
        cout << "\n> ";
        if (!getline(cin, command)) break;

        if (command == "exit") break;

        auto cmdTokens = tokenize(command);
        if (cmdTokens.empty()) continue;

        if (cmdTokens[0] == "download_file"){
            if (cmdTokens.size() < 4){ cout << "usage: download_file <group_id> <file_name> <destination_path>" << endl; continue; }
            if (!loggedIn.load()){ cout << "Please login first" << endl; continue; }
            thread(downloadFileThread, cmdTokens[1], cmdTokens[2], cmdTokens[3]).detach();
            cout << "Started downloading " << cmdTokens[2] << " in the background." << endl;
            continue;
        }

        if (cmdTokens[0] == "show_downloads"){
            cout << showDownloads() << endl;
            continue;
        }

        if (cmdTokens[0] == "stop_share"){
            if (cmdTokens.size() < 3){ cout << "usage: stop_share <group_id> <file_name>" << endl; continue; }
            cout << stopShare(cmdTokens[1], cmdTokens[2]) << endl;
            continue;
        }

        if (cmdTokens[0] == "upload_file"){
            if (cmdTokens.size() < 3){ cout << "usage: upload_file <group_id> <file_path> [description...]" << endl; continue; }
            string groupId = cmdTokens[1];
            string filePath = cmdTokens[2];

            // Anything typed after the path is a description, indexed in the
            // vector database so this file can be found by search_files later.
            string description;
            for(size_t i = 3; i < cmdTokens.size(); i++){
                if (i > 3) description += " ";
                description += cmdTokens[i];
            }

            char absPath[PATH_MAX];
            if (realpath(filePath.c_str(), absPath) != nullptr) filePath = string(absPath);

            size_t pos = filePath.find_last_of("/\\");
            string filename = (pos != string::npos) ? filePath.substr(pos + 1) : filePath;
            string fileKey = groupId + "_" + filename;

            string resp = sendToTracker("upload_file " + groupId + " " + filePath);
            cout << resp << endl;

            if (resp.rfind("OK", 0) == 0){
                struct stat st;
                if (stat(filePath.c_str(), &st) == 0){
                    long long fileSize = st.st_size;
                    long long totalChunks = (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
                    if (totalChunks == 0) totalChunks = 1;
                    {
                        lock_guard<mutex> lock(sharedLock);
                        sharedFiles[fileKey] = SeedInfo{filePath, totalChunks};
                    }
                    cout << "Now sharing " << filename << " with group " << groupId << "." << endl;
                }
                if (!description.empty()) indexFileDescription(fileKey, description);
            }
            continue;
        }

        if (cmdTokens[0] == "search_files"){
            if (cmdTokens.size() < 3){ cout << "usage: search_files <group_id> <description words...>" << endl; continue; }
            if (!loggedIn.load()){ cout << "Please login first" << endl; continue; }

            string queryText;
            for(size_t i = 2; i < cmdTokens.size(); i++){
                if (i > 2) queryText += " ";
                queryText += cmdTokens[i];
            }
            searchFilesByDescription(cmdTokens[1], queryText);
            continue;
        }

        if (cmdTokens[0] == "login"){
            if (cmdTokens.size() < 3){ cout << "usage: login <user_id> <password>" << endl; continue; }
            string cmd = command + " " + clientIp + " " + to_string(clientPort);
            string resp = sendToTracker(cmd);
            cout << resp << endl;
            if (resp.rfind("OK", 0) == 0){
                myUser = cmdTokens[1];
                myPass = cmdTokens[2];
                loggedIn = true;
            }
            continue;
        }

        if (cmdTokens[0] == "logout"){
            string resp = sendToTracker(command);
            cout << resp << endl;
            if (resp.rfind("OK", 0) == 0){
                loggedIn = false;
                myUser.clear();
                myPass.clear();
                lock_guard<mutex> lock(bgLock);
                if (bgSock >= 0){ close(bgSock); bgSock = -1; }
            }
            continue;
        }

        cout << sendToTracker(command) << endl;
    }

    if (trackerSock >= 0) close(trackerSock);
    lock_guard<mutex> lock(bgLock);
    if (bgSock >= 0) close(bgSock);
    return 0;
}

# Peer-to-Peer Distributed File Sharing System

A simple file sharing system, like a mini BitTorrent. Users create an
account, make groups, and share files inside those groups. Files are
not stored on one central server — they move directly between users,
in small pieces, from whoever already has them.

For the full architecture — component diagrams, sequence diagrams for every
event, and the protocol reference — see [ARCHITECTURE.md](ARCHITECTURE.md).

## Table of Contents

- [Introduction](#introduction)
- [Demo](#demo)
- [Methodology](#methodology)
- [File Structure](#file-structure)
- [Getting Started](#getting-started)
- [Good to Know](#good-to-know)

## Introduction

This project has two programs:

- **tracker** — keeps a list of users, groups, and which files exist.
  It does not store the files themselves, only who has them.
- **client** — the program a person actually runs. It logs in, joins
  groups, uploads files, and downloads files from other clients
  directly.

Two trackers run at the same time, side by side, so if one goes down
the system still works using the other one. They copy data to each
other in the background.

## Demo

A quick example of what using it looks like (typed at the client's
`>` prompt):

```
> create_user alice pw123
OK: user 'alice' registered successfully

> login alice pw123
OK: 'alice' logged in successfully

> create_group study
OK: group 'study' created

> upload_file study notes.txt
OK: uploaded 'notes.txt' (10240 bytes, 1 chunks)

> download_file study notes.txt ./notes_copy.txt
Started downloading notes.txt in the background.

> show_downloads
Done: notes.txt (group study)
```

## Methodology

**How a file moves between users:**

1. A file is split into fixed-size pieces (512 KB each).
2. Each piece gets its own checksum (SHA-1), plus one checksum for
   the whole file. The tracker stores these checksums.
3. When someone downloads, they ask the tracker who currently has the
   file, then pull pieces straight from those users, several pieces
   at once from different people.
4. Each piece is checked against its checksum right after it arrives.
   A piece that fails the check is thrown away and asked for again
   from someone else.
5. Pieces are picked using a "rarest first" rule — whichever piece
   the fewest people currently have is downloaded first. This spreads
   the work out instead of everyone grabbing the same piece at once.

**Why two trackers:**

Both trackers can answer any client directly — there's no "main" one
you must talk to. Every change is saved locally first, then copied to
the other tracker in the background, so a slow or dead second tracker
never blocks anyone. When a tracker reconnects after being offline, it
asks the other one for a full copy of the current state and merges it
in, so nothing gets lost.

**Client threads:** each client does three things at once — reads
commands typed by the user, listens for other clients asking for file
chunks, and runs downloads in the background. This is why you can keep
typing commands while a download is running.

**Sending messages:** every message sent over the network (tracker to
client, tracker to tracker, client to client) starts with 4 bytes
saying how long the message is. This way, the receiving side always
knows exactly where one message ends and the next begins.

## File Structure

```
.
├── tracker/
│   ├── tracker.cpp        # the tracker program
│   ├── common.h           # shared networking code
│   ├── Makefile
│   └── tracker_info.txt
├── client/
│   ├── client.cpp         # the client program
│   ├── common.h           # identical copy of the same file
│   ├── Makefile
│   └── tracker_info.txt
├── vectordb/               # a separate vector-search project that reuses this system's networking code - see vectordb/README.md
├── tracker_info.txt         # reference copy
└── README.md
```

## Getting Started

You need Linux (or WSL on Windows) with `g++`, `pthread`, and OpenSSL
dev headers (`libssl-dev` on Ubuntu/Debian, `openssl-devel` on
Fedora/RHEL).

**1. Build both programs:**

```bash
cd tracker && make
cd ../client && make
```

**2. Start both trackers** (in two separate terminals). The addresses
they use come from `tracker_info.txt`, which already has:

```
127.0.0.1:9105
127.0.0.1:9106
```

```bash
cd tracker
./tracker tracker_info.txt 1     # terminal 1
./tracker tracker_info.txt 2     # terminal 2
```

Type `quit` in a tracker's terminal to shut just that one down.

**3. Start one or more clients**, each with its own IP:PORT:

```bash
cd client
./client 127.0.0.1:9001 tracker_info.txt
./client 127.0.0.1:9002 tracker_info.txt
```

**Commands you can type at a client's `>` prompt:**

| Command | What it does |
|---|---|
| `create_user <user_id> <password>` | Make a new account |
| `login <user_id> <password>` | Log in |
| `logout` | Log out |
| `create_group <group_id>` | Make a new group (you become the owner) |
| `join_group <group_id>` | Ask to join a group |
| `leave_group <group_id>` | Leave a group |
| `list_groups` | Show every group |
| `list_requests <group_id>` | Owner only: see who wants to join |
| `accept_request <group_id> <user_id>` | Owner only: let someone in |
| `upload_file <group_id> <file_path> [description...]` | Share a file with a group. Anything typed after the path is a description, indexed for search |
| `list_files <group_id>` | Show files shared in a group |
| `search_files <group_id> <description words...>` | Find files by what they contain, not by exact name (needs the vector database - see below) |
| `download_file <group_id> <file_name> <dest_path>` | Download a file |
| `show_downloads` | Check download progress |
| `stop_share <group_id> <file_name>` | Stop sharing a file |
| `exit` | Close the client |

## Searching Files by Description

Normally you can only get a file if you know its exact name. This part lets
you find files by describing them instead — and it's where the two halves of
this project actually work together: the file-sharing client stores each
file's description in the vector database (`vectordb/`), then searches those
descriptions later.

**How it works:** the client turns a description into a 32-number vector by
hashing each word into one of 32 buckets and counting it, then scaling the
result to unit length. Files with similar descriptions end up as similar
vectors, so the vector database's nearest-neighbour search finds them. No
trained model and no extra libraries — just word overlap turned into
distance.

**1. Start the vector database** (3 raft nodes + 3 peers, using the 32-dimension
config made for this). From `vectordb/raft/`:

```bash
./raft_server peerA ../file_search_config.txt
./raft_server peerB ../file_search_config.txt
./raft_server peerC ../file_search_config.txt
```

Then from `vectordb/`:

```bash
./peer peerA file_search_config.txt data_peerA
./peer peerB file_search_config.txt data_peerB
./peer peerC file_search_config.txt data_peerC
```

**2. Start the client with the vector database addresses** (third argument):

```bash
cd client
./client 127.0.0.1:9001 tracker_info.txt vectordb_info.txt
```

**3. Upload files with a description, then search:**

```
> upload_file team /tmp/report.txt annual budget spreadsheet with revenue and expense numbers
> upload_file team /tmp/photos.txt vacation photos from the beach trip in summer
> upload_file team /tmp/notes.txt university lecture notes about python programming

> search_files team revenue budget numbers
 1. report.txt  (distance 0.734443)  "annual budget spreadsheet with revenue and expense numbers"
 2. notes.txt   (distance 1.236363)  "university lecture notes about python programming"
 3. photos.txt  (distance 1.278613)  "vacation photos from the beach trip in summer"
```

The closest match comes first. Results are limited to files in the group you
name, and only files uploaded *with* a description are searchable.

The third argument is optional — leave it out and the client behaves exactly
as before, just without `search_files`.

## Good to Know

- Everything runs over plain TCP sockets, no encryption — passwords
  are hashed before the tracker stores them, but sent in plain text
  over the wire.
- User IDs, group IDs, and filenames should not contain spaces.
- Only one client can be logged in as a given user at a time; logging
  in again from a new client takes over that user's session.
- If a client's process restarts, it needs to `upload_file` the same
  file again to resume sharing it — the tracker remembers the file
  either way.

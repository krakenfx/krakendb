/**
 * Kraken audit DB utility program driver
 *
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Payward, Inc. (Kraken.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "db.h"

enum { MODE_ROOT, MODE_POSITION, MODE_HASH, MODE_DUMP, MODE_GENTESTDATA };

void ShowHex(const unsigned char* data, size_t datalen)
{
	int i;
	for(i=0; i<datalen; ++i)
		fprintf(stdout, "%02x%s", data[i], 31==(i&31) ? "\n" : "");
	if((i&31)) printf("\n");
}

bool HexData(const char* hex, unsigned char* data, size_t maxlen)
{
	const char* s;
	int datapos = 0;
	unsigned char num;

	for(s=hex; s[0] && s[1]; s+=2) {
		if(s[0]>='0' && s[0]<='9') num = s[0] - '0';
		else if(s[0]>='A' & s[0]<='F') num = s[0] - 'A' + 10;
		else if(s[0]>='a' & s[0]<='f') num = s[0] - 'a' + 10;
		else return false;
		num <<= 4;

		if(s[1]>='0' && s[1]<='9') num |= s[1] - '0';
		else if(s[1]>='A' & s[1]<='F') num |= s[1] - 'A' + 10;
		else if(s[1]>='a' & s[1]<='f') num |= s[1] - 'a' + 10;
		else return false;

		if(datapos>=maxlen) return false;
		data[datapos++] = num;
	}

	return true;
}

bool GenTestData(const char* dbname)
{
	char buf[256];
	FILE* f;
	static long testdata[] = {
		1000, 2000, 3000, 5000, -2000, 8000, 4000, 2000
	};
	dbheader_t header = {
		{ 'K', 'A', 'D', 'D' }, sizeof(testdata) / sizeof(*testdata)
	};

	snprintf(buf, sizeof(buf), "%s.data", dbname);
	if(!(f=fopen(buf, "wx"))) {
		fprintf(stderr, "Could not create file %s\n", buf);
		return false;
	}
	if(1!=fwrite(&header, sizeof(header), 1, f) ||
			1!=fwrite(testdata, sizeof(testdata), 1, f)) {
		fprintf(stderr, "Could not write to file %s\n", buf);
		fclose(f);
		unlink(buf);
		return false;
	}

	fclose(f);

	// delete tree file so tree can be regenerated
	snprintf(buf, sizeof(buf), "%s.tree", dbname);
	unlink(buf);
	return true;
}

int main(int argc, char* argv[])
{
	const char* dbname;
	const char* verifykey = NULL;
	union {
		unsigned char buf[64];
		uint256_t hash;
	};
	std::vector<node_t> nodes;
	std::vector<node_t>::const_iterator it;
	int idx, pos;
	int mode = MODE_ROOT;
	char *ptr;
	DB* db;

	if(argc<2) {
		fprintf(stderr, "Usage: %s <dbname> [key=verifier key] [<position>|<hash>|root|dump|gendata]\n", argv[0]);
		return 0;
	}

	dbname = argv[1];

	for(idx=2; idx<argc; ++idx) {
		if(!strncmp(argv[idx], "key=", 4)) {
			verifykey = argv[idx] + 4;
		} else if(!strcmp(argv[idx], "dump")) {
			mode = MODE_DUMP;
		} else if(!strcmp(argv[idx], "root")) {
			mode = MODE_ROOT;
		} else if(!strcmp(argv[idx], "gendata")) {
			mode = MODE_GENTESTDATA;
		} else if(sizeof(uint256_t)*2==strlen(argv[idx])) {
			if(!HexData(argv[idx], buf, sizeof(buf))) {
				fprintf(stderr, "Invalid hash value: %s\n", argv[idx]);
				return 0;
			}
			mode = MODE_HASH;
		} else if(argv[idx][0]>='0' && argv[idx][0]<='9') {
			pos = strtol(argv[idx], &ptr, 10);
			if(ptr && *ptr) {
				fprintf(stderr, "Invalid position value: %s\n", argv[idx]);
				return 0;
			}
			mode = MODE_POSITION;
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[idx]);
			return 0;
		}
	}

	if(MODE_GENTESTDATA==mode) {
		if(!GenTestData(dbname))
			fprintf(stderr, "Error generating data\n");
	}

	db = new DB(dbname, verifykey);
	if(!db->Open()) {
		fprintf(stderr, "Open DB failed\n");
		delete(db);
		return 0;
	}

	switch(mode) {
	case MODE_HASH:
		if(db->GetNodes(hash, nodes)) {
			idx = 0;
			for(it=nodes.begin(); it!=nodes.end(); ++it) {
				fprintf(stdout, "%d: ", idx++);
				ShowHex(it->hash, sizeof(it->hash));
			}
		} else
			fprintf(stderr, "Hash not found\n");

		break;
	case MODE_POSITION:
		if(db->GetNodes(pos, nodes)) {
			idx = 0;
			for(it=nodes.begin(); it!=nodes.end(); ++it) {
				fprintf(stdout, "%d: ", idx++);
				ShowHex(it->hash, sizeof(it->hash));
			}
		} else
			fprintf(stderr, "Error reading tree\n");

		break;
	case MODE_ROOT:
		if(db->GetRoot(nodes)) {
			fprintf(stdout, "Root %ld: ", nodes[2].data.value);
			ShowHex(nodes[2].hash, sizeof(nodes[2].hash));
			fprintf(stdout, "Left: ");
			ShowHex(nodes[0].hash, sizeof(nodes[0].hash));
			fprintf(stdout, "Right: ");
			ShowHex(nodes[1].hash, sizeof(nodes[1].hash));
		} else
			fprintf(stderr, "Error reading tree\n");

		break;
	case MODE_DUMP:
		if(!db->Dump())
			fprintf(stderr, "Error reading tree\n");
		break;
	}

	return 1;
}

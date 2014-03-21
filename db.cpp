/**
 * Kraken audit DB functions
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
#include <openssl/sha.h>
#include "db.h"

#define DATAHEADER	"KADD"
#define TREEHEADER	"KADT"

void ShowHex(const unsigned char* data, size_t datalen);

DB::DB(const char* dbname, const char* verifykey): fd_(NULL), numRecords_(0)
{
	(char*&)dbname_ = strdup(dbname ? dbname : "krakendb");
	(char*&)verifykey_ = verifykey ? strdup(verifykey) : NULL;
	verifykeylen_ = verifykey_ ? strlen(verifykey_) : 0;
}

DB::~DB()
{
	free((char*)dbname_);
	free((char*)verifykey_);
	if(fd_) fclose(fd_);
}

bool DB::Open()
{
	char buf[256], buf2[256];
	dbheader_t header;
	long fsize;

	// open tree file
	snprintf(buf, sizeof(buf), "%s.data", dbname_);
	snprintf(buf2, sizeof(buf2), "%s.tree", dbname_);
	if(!(fd_=fopen(buf2, "rb"))) {
		// attempt to generate tree file if not found
		if(!generateTree(buf, buf2))
			return false;

		fd_ = fopen(buf2, "rb");
	}

	if(!fd_) return false;

	// verify header
	if(1!=fread(&header, sizeof(header), 1, fd_) ||
			memcmp(header.signature, TREEHEADER, sizeof(header.signature)) ||
			header.numrecords<=1 ||
			fseek(fd_, 0, SEEK_END)<0 || (fsize=ftell(fd_))<0 ||
			((header.numrecords * 2 - 1) * sizeof(node_t) + sizeof(dbheader_t))!=fsize ||
			(header.numrecords & (header.numrecords-1))) {
		fprintf(stderr, "Bad tree file %s\n", buf2);
		fclose(fd_);
		fd_ = NULL;
		return false;
	}

	fprintf(stdout, "Using db %s\n", dbname_);

	numRecords_ = header.numrecords;
	return !!fd_;
}

bool DB::Dump()
{
	node_t nodes[512];
	int i, pos, len;
	int total = numRecords_ * 2 - 1;

	if(!fd_ || fseek(fd_, sizeof(dbheader_t), SEEK_SET)<0)
		return false;

	len = sizeof(nodes) / sizeof(*nodes);
	for(pos=0; pos<total; pos+=len) {
		if(pos+len>total)
			len = total - pos;

		if(len!=fread(nodes, sizeof(*nodes), len, fd_))
			return false;

		for(i=0; i<len; ++i)
			ShowHex(nodes[i].hash, sizeof(nodes[i].hash));
	}
	return true;
}

bool DB::GetRoot(std::vector<node_t>& nodes)
{
	node_t nodesdata[3];

	if(!fd_) return false;

	if(fseek(fd_, (numRecords_ * 2 - 3 - 1) * sizeof(node_t) + sizeof(dbheader_t), SEEK_SET)<0)
		return false;
	if(3!=fread(&nodesdata, sizeof(*nodesdata), 3, fd_))
		return false;

	nodes.clear();
	nodes.push_back(nodesdata[0]);
	nodes.push_back(nodesdata[1]);
	nodes.push_back(nodesdata[2]);
	return true;
}

bool DB::GetNodes(int pos, std::vector<node_t>& nodes)
{
	node_t node;
	unsigned int depthpos, depthlen;

	if(!fd_ || pos<0 || pos>=numRecords_) return false;

	depthlen = numRecords_;
	depthpos = 0;
	nodes.clear();
	while(depthlen>0) {
		if(fseek(fd_, (depthpos + pos) * sizeof(node) + sizeof(dbheader_t), SEEK_SET)<0)
			return false;
		if(1!=fread(&node, sizeof(node), 1, fd_))
			return false;

		nodes.push_back(node);
		pos = pos / 2;
		depthpos += depthlen;
		depthlen = depthlen / 2;
	}
	return true;
}

bool DB::GetNodes(const uint256_t& hash, std::vector<node_t>& nodes)
{
	node_t nodesdata[512];
	int i, pos, len;

	if(!fd_ || fseek(fd_, sizeof(dbheader_t), SEEK_SET)<0)
		return false;

	len = sizeof(nodesdata) / sizeof(*nodesdata);
	for(pos=0; pos<numRecords_; pos+=len) {
		if(pos+len>numRecords_)
			len = numRecords_ - pos;

		if(len!=fread(nodesdata, sizeof(*nodesdata), len, fd_))
			return false;

		for(i=0; i<len; ++i) {
			if(!memcmp(hash, nodesdata[i].hash, sizeof(hash)))
				return GetNodes(pos + i, nodes);
		}
	}
	return false;
}

bool DB::generateTree(const char* infile, const char* outfile)
{
	union {
		node_t nodes[3];
		dbheader_t header;
	};
	FILE *fin, *fout = NULL;
	long fsize;
	unsigned int i, total;

	if(!verifykey_) {
		fprintf(stderr, "No verifier key to generate tree with\n");
		return false;
	}

	fprintf(stderr, "Generating tree file from %s\n", infile);

	// open input data file
	if(!(fin=fopen(infile, "rb")))
		return false;

	if(1!=fread(&header, sizeof(dbheader_t), 1, fin)) {
		fprintf(stderr, "Could not read input header\n");
		goto fail;
	}

	if(memcmp(header.signature, DATAHEADER, sizeof(header.signature))) {
		fprintf(stderr, "Invalid data file\n");
		goto fail;
	}

	if(fseek(fin, 0, SEEK_END)<0 || (fsize=ftell(fin))<0 || header.numrecords<=1 ||
			(header.numrecords * sizeof(dbdata_t) + sizeof(dbheader_t))!=fsize ||
			(header.numrecords & (header.numrecords-1))) {	// numrecords must be a power of 2
		fprintf(stderr, "Invalid record count for data file\n");
		goto fail;
	}
	numRecords_ = header.numrecords;

	// open output data file
	if(!(fout=fopen(outfile, "w+b"))) {
		fprintf(stderr, "Could not create tree file %s\n", outfile);
		goto fail;
	}

	// write header
	memcpy(header.signature, TREEHEADER, sizeof(header.signature));
	if(1!=fwrite(&header, sizeof(header), 1, fout)) {
		fprintf(stderr, "Could not write header for tree file\n");
		goto fail;
	}

	// generate tree
	// write the leaf nodes first
	if(fseek(fin, sizeof(dbheader_t), SEEK_SET)<0) {
		fprintf(stderr, "Could not seek in data file\n");
		goto fail;
	}
	for(i=0; i<numRecords_; ++i) {
		if(1!=fread(&nodes[0].data.value, sizeof(nodes[0].data.value), 1, fin)) {
			fprintf(stderr, "Read data %d failed\n", i);
			goto fail;
		}
		hashData(nodes[0], i);
		if(1!=fwrite(&nodes[0], sizeof(nodes[0]), 1, fout)) {
			fprintf(stderr, "Write data %d failed\n", i);
			goto fail;
		}
	}

	// write the rest of the tree
	for(i=0; i<numRecords_-1; ++i) {
		if(fseek(fout, i * 2 * sizeof(node_t) + sizeof(dbheader_t), SEEK_SET)<0) {
			fprintf(stderr, "Seek tree failed\n");
			goto fail;
		}
		if(2!=fread(nodes, sizeof(node_t), 2, fout)) {
			fprintf(stderr, "Read tree failed\n");
			goto fail;
		}
		hashNode(nodes[0], nodes[1], nodes[2]);

		if(fseek(fout, 0, SEEK_END)<0) {
			fprintf(stderr, "Seek write tree failed\n");
			goto fail;
		}
		if(1!=fwrite(&nodes[2], sizeof(nodes[2]), 1, fout)) {
			fprintf(stderr, "Write tree failed\n");
			goto fail;
		}
	}

	fclose(fout);
	fclose(fin);
	return true;

fail:
	fclose(fin);
	if(fout) {
		fclose(fout);
		unlink(outfile);
	}
	return false;
}

unsigned long DB::getDataCode(int datapos) const
{
	// NOTE: this should be updated to generate/retrieve the user's data code
	return 0;
}

void DB::hashData(node_t& node, int pos) const
{
	unsigned long code = getDataCode(pos);
	char buf[64];

	// perform SHA256(SHA256("<code>:<value>"))
	snprintf(buf, sizeof(buf), "%016lx:%ld", code, node.data.value);
	SHA256((unsigned char*)buf, strlen(buf), node.hash);
	SHA256(node.hash, sizeof(node.hash), node.hash);
	if(node.data.value<0)
		fprintf(stderr, "Notice: data %d contains a negative value of %ld\n", pos, node.data.value);
}

void DB::hashNode(const node_t& node1, const node_t& node2, node_t& noderes) const
{
	SHA256_CTX ctx;

	// perform SHA256(SHA256(LE(node1.value + node2.value) || verifykey || node1.hash || node2.hash) || verifykey)
	noderes.data.value = node1.data.value + node2.data.value;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, &noderes.data.value, sizeof(noderes.data.value));	// assumed to be little-endian
	if(verifykeylen_>0) SHA256_Update(&ctx, verifykey_, verifykeylen_);
	SHA256_Update(&ctx, node1.hash, sizeof(node1.hash));
	SHA256_Update(&ctx, node2.hash, sizeof(node2.hash));
	SHA256_Final(noderes.hash, &ctx);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, noderes.hash, sizeof(noderes.hash));
	if(verifykeylen_>0) SHA256_Update(&ctx, verifykey_, verifykeylen_);
	SHA256_Final(noderes.hash, &ctx);
}

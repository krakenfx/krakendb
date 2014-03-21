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

#ifndef _DB_H_
#define _DB_H_

#include <vector>
#include <stdint.h>

typedef unsigned char uint256_t[32];

typedef struct {
	int64_t		value;
} dbdata_t;

typedef struct {
	uint256_t	hash;
	dbdata_t	data;
} node_t;

typedef struct {
	char		signature[4];
	unsigned int numrecords;
} dbheader_t;

class DB
{
public:
	DB(const char* dbname, const char* verifykey=NULL);
	~DB();

	// open the db, generating the tree from a data file if necessary
	bool Open();

	// dump all node hashes for the tree
	bool Dump();

	// returns the left, right, and root nodes of the tree
	bool GetRoot(std::vector<node_t>& tree);

	// gets the nodes from a leaf position to the root
	bool GetNodes(int pos, std::vector<node_t>& nodes);

	// gets the nodes from a leaf hash to the root
	// NOTE: hashes aren't necessarily unique
	bool GetNodes(const uint256_t& hash, std::vector<node_t>& nodes);

protected:
	FILE* fd_;
	const char* dbname_;
	const char* verifykey_;
	size_t verifykeylen_;
	unsigned int numRecords_;

	// generate the tree using a data file
	bool generateTree(const char* infile, const char* outfile);

	// generate a data code based on the leaf position
	unsigned long getDataCode(int datapos) const;

	// generate the hash for a leaf data node
	void hashData(node_t& node, int pos) const;

	// generate the parent hash node from the left and right child nodes
	void hashNode(const node_t& node1, const node_t& node2, node_t& noderes) const;
};

#endif // _DB_H_

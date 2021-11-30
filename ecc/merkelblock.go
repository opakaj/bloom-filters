package ecc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"strings"
)

type MerkleTree struct {
	total        float64
	maxDepth     float64
	nodes        []string
	currentDepth int
	currentIndex int
}

func NewMerkleTree(total float64) (Mt *MerkleTree) {
	Mt = new(MerkleTree)
	Mt.total = total
	Mt.maxDepth = math.Ceil(math.Log(Mt.total)) //removed base two
	//Mt.nodes = nodes
	for depth := 0; depth < int(Mt.maxDepth)+1; depth++ {
		numItems := math.Ceil(float64(Mt.total) / math.Pow(2, Mt.maxDepth-float64(depth)))
		levelHashes := func(repeated []string, n int) (result []string) {
			for i := 0; i < n; i++ {
				result = append(result, repeated...)
			}
			return result
		}([]string{}, int(numItems))
		Mt.nodes = append(Mt.nodes, levelHashes...)
	}
	Mt.currentDepth = 0
	Mt.currentIndex = 0
	return
}

func (Mt *MerkleTree) Repr() string {
	var result []string
	var short string
	for depth, level := range Mt.nodes {
		var items []string
		for index, h := range level {
			if &h == nil {
				short = "None"
			} else {
				hx := hex.EncodeToString([]byte(string(h)))
				short = fmt.Sprintf("%x...", hx[:8])
			}
			if depth == Mt.currentDepth && index == Mt.currentIndex {
				items = append(items, "%s", short[:len(short)-2])
			} else {
				items = append(items, "%s", short)
			}
		}
		result = append(result, strings.Join(items, ", "))
	}
	return strings.Join(result, "\n")
}

func (Mt *MerkleTree) up() {
	Mt.currentDepth -= 1
	Mt.currentIndex /= 2
}

func (Mt *MerkleTree) left() {
	Mt.currentDepth += 1
	Mt.currentIndex *= 2
}

func (Mt *MerkleTree) right() {
	Mt.currentDepth += 1
	Mt.currentIndex = Mt.currentIndex*2 + 1
}

func (Mt *MerkleTree) root() byte {
	return Mt.nodes[0][0]
}

func (Mt *MerkleTree) getRightNode() byte {
	return Mt.nodes[Mt.currentDepth+1][Mt.currentIndex*2+1]
}

func (Mt *MerkleTree) getLeftNode() byte {
	return Mt.nodes[Mt.currentDepth+1][Mt.currentIndex*2]
}

func (Mt *MerkleTree) setCurrentNode(value string) bool {
	return string(Mt.nodes[Mt.currentDepth][Mt.currentIndex]) == value
}

func (Mt *MerkleTree) getCurrentNode() byte {
	return Mt.nodes[Mt.currentDepth][Mt.currentIndex]
}

func (Mt *MerkleTree) isLeaf() bool {
	return float64(Mt.currentDepth) == Mt.maxDepth
}

func (Mt *MerkleTree) rightExists() bool {
	return len(Mt.nodes[Mt.currentDepth+1]) > Mt.currentIndex*2+1
}

func (Mt *MerkleTree) populateTree(flagBits []int, hashes []string) {
	for Mt.root() == 0 {
		if Mt.isLeaf() {
			func(s *[]int, i int) int {
				popped := (*s)[i]
				*s = append((*s)[:i], (*s)[i+1:]...)
				return popped
			}(&flagBits, 0)
			Mt.setCurrentNode(func(s *[]string, i int) string {
				popped := (*s)[i]
				*s = append((*s)[:i], (*s)[i+1:]...)
				return popped
			}(&hashes, 0))
			Mt.up()
		} else {
			leftHash := Mt.getLeftNode()
			if &leftHash == nil {
				if reflect.DeepEqual(func(s *[]int, i int) int {
					popped := (*s)[i]
					*s = append((*s)[:i], (*s)[i+1:]...)
					return popped
				}(&flagBits, 0), 0) {
					Mt.setCurrentNode(func(s *[]string, i int) string {
						popped := (*s)[i]
						*s = append((*s)[:i], (*s)[i+1:]...)
						return popped
					}(&hashes, 0))
					Mt.up()
				} else {
					Mt.left()
				}
			} else if Mt.rightExists() {
				rightHash := Mt.getRightNode()
				if &rightHash == nil {
					Mt.right()
				} else {
					Mt.setCurrentNode(merkleParent(string(leftHash), string(rightHash)))
					Mt.up()
				}
			} else {
				Mt.setCurrentNode(merkleParent(string(leftHash), string(leftHash)))
				Mt.up()
			}
		}
	}
	if len(hashes) != 0 {
		panic(fmt.Errorf("RuntimeError: %v", "hashes not all consumed {}", len(hashes)))
	}
	for _, flag_bit := range flagBits {
		if flag_bit != 0 {
			panic(fmt.Errorf("RuntimeError: %v", "flag bits not all consumed"))
		}
	}
}

type MerkleBlock struct {
	version    int64
	prevBlock  string
	merkleRoot string
	timestamp  int64
	bits       []byte
	nonce      []byte
	total      int
	hashes     []string
	flags      []byte
}

func NewMerkleBlock(version int64, prevBlock string, merkleRoot string,
	timestamp int64,
	bits []byte,
	nonce []byte,
	total int,
	hashes []string,
	flags []byte,
) (Mb *MerkleBlock) {
	Mb = new(MerkleBlock)
	Mb.version = version
	Mb.prevBlock = prevBlock
	Mb.merkleRoot = merkleRoot
	Mb.timestamp = timestamp
	Mb.bits = bits
	Mb.nonce = nonce
	Mb.total = total
	Mb.hashes = hashes
	Mb.flags = flags
	return
}

func (Mb *MerkleBlock) Repr() string {
	result := fmt.Sprintf("%d\n", Mb.total)
	for _, h := range Mb.hashes {
		result += fmt.Sprintf("\t%x\n", h)
	}
	return result + fmt.Sprintf("{%x}", Mb.flags)
}

func (Mb *MerkleBlock) parse(s []byte) *MerkleBlock {
	var byt bytes.Buffer
	byt.Write(s)
	a, _ := byt.ReadBytes(4)
	version := littleEndianToInt(a)
	b, _ := byt.ReadBytes(32)
	prevBlock := reverse(string(b))
	c, _ := byt.ReadBytes(32)
	merkleRoot := reverse(string(c))
	d, _ := byt.ReadBytes(4)
	timestamp := littleEndianToInt(d)
	bits, _ := byt.ReadBytes(4)
	nonce, _ := byt.ReadBytes(4)
	e, _ := byt.ReadBytes(4)
	total := littleEndianToInt(e)
	numHashes := readVarint(s)
	var hashes []string
	for i := 0; i < int(numHashes); i++ {
		x, _ := byt.ReadBytes(32)
		hashes = append(hashes, reverse(string(x)))
	}
	flagsLength := readVarint(s)
	flags, _ := byt.ReadBytes(byte(flagsLength))
	return NewMerkleBlock(version, prevBlock, merkleRoot, timestamp, bits, nonce, int(total), hashes, flags)
}

func (Mb *MerkleBlock) isValid() bool {
	flagBits := bytesToBitField(Mb.flags)
	hashes := func() (elts []string) {
		for _, h := range Mb.hashes {
			elts = append(elts, reverse(h))
		}
		return
	}()
	merkleTree := NewMerkleTree(float64(Mb.total))
	merkleTree.populateTree(flagBits, hashes)
	return reverse(string(merkleTree.root())) == Mb.merkleRoot
}

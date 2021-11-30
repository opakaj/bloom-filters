package ecc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"unsafe"

	"github.com/btcsuite/btcutil"
)

var SIGHASHALL = 1
var SIGHASHNONE = 2
var SIGHASHSINGLE = 3
var BASE58ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
var TWOWEEKS = 60 * 60 * 24 * 14
var MAXTARGET = 65535 * math.Pow(256, 29-3)

func hash160(s string) string {
	return hex.EncodeToString(btcutil.Hash160([]byte(s)))
}

func hash256(s string) string {
	//two rounds of sha256
	hash := sha256.Sum256([]byte(s))
	hash = sha256.Sum256(hash[:])
	return hex.EncodeToString(hash[:]) //convet to [] by slicicng it
}

func divmod(numerator, denominator int64) (quotient, remainder int64) {
	quotient = numerator / denominator // integer division, decimals are truncated
	remainder = numerator % denominator
	return
}

func ByteArrayToInt(arr []byte) int64 {
	val := int64(0)
	size := len(arr)
	for i := 0; i < size; i++ {
		*(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&val)) + uintptr(i))) = arr[i]
	}
	return val
}

func encodeBase58(s string) string {
	count := 0
	for _, c := range s {
		if c == 0 {
			count += 1
		} else {
			break
		}
	}
	num := binary.BigEndian.Uint32([]byte(s)) //bytes to int
	prefix := strings.Repeat("1", count)
	result := ""
	for num > 0 {
		_, mod := divmod(int64(num), 58)
		result = string(BASE58ALPHABET[mod]) + result
	}
	return prefix + result
}

func encodeBase58Checksum(b string) string {
	return encodeBase58(b + hash256(b)[:4])
}

func decodeBase58(s string) string {
	num := 0
	for _, c := range s {
		num *= 58
		num += func() int {
			for i, val := range BASE58ALPHABET {
				if val == c {
					return i
				}
			}
			panic(errors.New("ValueError: element not found"))
		}()
	}
	combined := make([]byte, 25)
	binary.BigEndian.PutUint64(combined, uint64(num)) //int to bytes
	checksum := combined[len(combined)-4:]
	if hash256(string(combined[:len(combined)-4]))[:4] != string(checksum) {
		panic(
			fmt.Errorf("bad address: %s %s", checksum, hash256(string(combined[:len(combined)-4]))[:4]),
		)
	}
	return string(combined[1 : len(combined)-4])
}

func littleEndianToInt(b []byte) int64 {
	//little_endian_to_int takes byte sequence as a little-endian number.
	//Returns an integer

	return int64(binary.BigEndian.Uint32(b)) //bytes to int
}

func intToLittleEndian(n, length int) []byte {
	//endian_to_little_endian takes an integer and returns the little-endian
	//byte sequence of length"

	x := make([]byte, length)
	binary.LittleEndian.PutUint64(x, uint64(n)) //int to bytes
	return x
}

func readVarint(s []byte) int64 {
	//read_varint reads a variable integer from a stream
	var byt bytes.Buffer
	byt.Write(s)

	i, _ := byt.ReadByte()

	if i == 253 {
		// 0xfd means the next two bytes are the number
		x, _ := byt.ReadBytes(2)
		return littleEndianToInt(x)
	} else if i == 254 {
		// 0xfe means the next two bytes are the number
		x, _ := byt.ReadBytes(4)
		return littleEndianToInt(x)
	} else if i == 255 {
		// 0xfe means the next two bytes are the number
		x, _ := byt.ReadBytes(8)
		return littleEndianToInt(x)
	} else {
		//anything else is just the integer
		return int64(i)
	}

}

func encodeVarint(i int) []byte {
	//encodes an integer as a varint
	if i < 253 {
		bs := make([]byte, 4)
		binary.BigEndian.PutUint32(bs, uint32(i)) //not so sure big or little
		return bs
	} else if i < 65536 {
		return append([]byte("\u00fd"), intToLittleEndian(i, 2)...)
	} else if i < 4294967296 {
		return append([]byte("\u00fe"), intToLittleEndian(i, 4)...)
	} else if i < 18446744073709551616 {
		return append([]byte("\u00ff"), intToLittleEndian(i, 8)...)
	} else {
		panic(fmt.Errorf("ValueError: %v", "integer too large: %d", i))
	}
}

func targetToBits(target int) []byte {
	var coefficient []byte
	var exponent int
	//"Turns a target integer back into bits"
	rawBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(rawBytes, uint64(target)) //int to bytes
	rawBytes = []byte(strings.TrimLeft(string(rawBytes), string([]byte("\u0000"))))
	if rawBytes[0] > 127 {
		exponent = len(rawBytes) + 1
		coefficient = append([]byte("\u0000"), rawBytes[:2]...)
	} else {
		exponent = len(rawBytes)
		coefficient = rawBytes[:3]
	}
	expo := make([]byte, 32)
	binary.BigEndian.PutUint64(expo, uint64(exponent))

	new_bits := append(coefficient[:], expo...)
	return new_bits
}

func bitsToTarget(bits []byte) int64 {
	exponent := bits[len(bits)-1]
	coefficient := littleEndianToInt(bits[:len(bits)-1])
	return coefficient * int64(math.Pow(256, float64(exponent-3)))
}

func calculateNewBits(previousBits []byte, timeDifferential int) []byte {
	if int(timeDifferential) > TWOWEEKS*4 {
		timeDifferential = TWOWEEKS * 4
	}
	if float64(timeDifferential) < math.Floor(float64(TWOWEEKS)/float64(4)) {
		timeDifferential = int(math.Floor(float64(TWOWEEKS) / float64(4)))
	}
	newTarget := math.Floor(float64((bitsToTarget(previousBits) * int64(timeDifferential)) / int64(TWOWEEKS)))
	return targetToBits(int(newTarget))
}

func merkleParent(hash1 string, hash2 string) string {
	//"Takes the binary hashes and calculates the hash256"
	return hash256(hash1 + hash2)
}

func merkleParentLevel(hashes []string) []string {
	//"Takes a list of binary hashes and returns a list that's half\n    the length"
	if len(hashes) == 1 {
		panic(fmt.Errorf("RuntimeError: %v", "Cannot take a parent level with only 1 item"))
	}
	if len(hashes)%2 == 1 {
		hashes = append(hashes, hashes[len(hashes)-1])
	}
	var parentLevel []string
	for i := 0; i < len(hashes); i += 2 {
		parent := merkleParent(hashes[i], hashes[i+1])
		parentLevel = append(parentLevel, parent)
	}
	return parentLevel
}

func merkleRoot(hashes []string) string {
	//"Takes a list of binary hashes and returns the merkle root
	currentLevel := hashes
	for len(currentLevel) > 1 {
		currentLevel = merkleParentLevel(currentLevel)
	}
	return currentLevel[0]
}

func bitFieldToBytes(bitField []int) []byte {
	if len(bitField)%8 != 0 {
		panic(
			fmt.Errorf(
				"RuntimeError: %v",
				"bit_field does not have a length that is divisible by 8",
			),
		)
	}
	result := make([]float64, 2)
	result = append(result, math.Floor(len(float64(bitField))/float64(8))...)
	for i, bit := range bitField {
		byte_index, bit_index := divmod(int64(i), 8)
		if bit == 1 {
			result[byte_index] |= 1 << bit_index
		}
	}
	return []byte(result)
}

func bytesToBitField(someBytes []byte) []int {
	flagBits := []int{}
	for _, byte := range someBytes {
		for i := 0; i < 8; i++ {
			flagBits = append(flagBits, int(byte&1))
			byte >>= 1
		}
	}
	return flagBits
}

func murmur3(data []int, seed int) int {
	//"from http://stackoverflow.com/questions/13305290/is-there-a-pure-python-implementation-of-murmurhash"
	c1 := 3432918353
	c2 := 461845907
	length := len(data)
	h1 := seed
	roundedEnd := length & 4294967292
	for i := 0; i < roundedEnd; i += 4 {
		k1 := data[i]&255 | data[i+1]&255<<8 | data[i+2]&255<<16 | data[i+3]<<24
		k1 *= c1
		k1 = k1<<15 | k1&4294967295>>17
		k1 *= c2
		h1 ^= k1
		h1 = int(h1)<<13 | int(h1)&4294967295>>19
		h1 = int(h1)*5 + 3864292196
	}
	k1 := 0
	val := length & 3
	if val == 3 {
		k1 = data[roundedEnd+2] & 255 << 16
	}
	if func() int {
		for i, v := range []int{2, 3} {
			if v == val {
				return i
			}
		}
		return -1
	}() != -1 {
		k1 |= data[roundedEnd+1] & 255 << 8
	}
	if func() int {
		for i, v := range []int{1, 2, 3} {
			if v == val {
				return i
			}
		}
		return -1
	}() != -1 {
		k1 |= data[roundedEnd] & 255
		k1 *= c1
		k1 = k1<<15 | k1&4294967295>>17
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= length
	h1 ^= int(h1) & 4294967295 >> 16
	h1 *= 2246822507
	h1 ^= int(h1) & 4294967295 >> 13
	h1 *= 3266489909
	h1 ^= int(h1) & 4294967295 >> 16
	return int(h1) & 4294967295
}

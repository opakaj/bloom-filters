package ecc

type BloomFilter struct {
	size          int
	bitField      []int
	functionCount int
	tweak         int
}

var BIP37CONSTANT = 4221880213

func NewBloomFilter(size int, functionCount int, tweak int) (Bf *BloomFilter) {
	Bf = new(BloomFilter)
	Bf.size = size
	Bf.bitField = func(repeated []int, n int) (result []int) {
		for i := 0; i < n; i++ {
			result = append(result, repeated...)
		}
		return result
	}([]int{0}, int(size)*8)
	Bf.functionCount = functionCount
	Bf.tweak = tweak
	return
}

func (Bf *BloomFilter) add(item []int) {
	for i := 0; i < Bf.functionCount; i++ {
		seed := i*BIP37CONSTANT + Bf.tweak
		h := murmur3(item, seed)
		bit := h % (Bf.size * 8)
		Bf.bitField[bit] = 1
	}
}

func (Bf *BloomFilter) filterload(flag int) *GenericMessage {
	payload := encodeVarint(Bf.size)
	payload = append(payload, Bf.filterBytes()...)
	payload = append(payload, intToLittleEndian(Bf.functionCount, 4)...)
	payload = append(payload, intToLittleEndian(Bf.tweak, 4)...)
	payload = append(payload, intToLittleEndian(flag, 1)...)
	return NewGenericMessage([]byte("filterload"), payload)
}

func (Bf *BloomFilter) filterBytes() []byte {
	return bitFieldToBytes(Bf.bitField)
}

// This is free and unencumbered software released into the public domain.

// Package chacha implements the ChaCha stream cipher.
package chacha

import (
    "crypto/cipher"
    "encoding/binary"
    "errors"
    "io"
)

// avail replaced with nextByte by Ron Charlton, public domain 2022-09-06,
// for a 25 percentage point speedup.
// Ron Charlton re-coded method 'next' to use simple variables instead of an
// array, for 30% less execution time on an M2 Max Mac Studio. Public domain,
// 2024-11-10.

// Cipher is an instance of the ChaCha stream cipher. It implements both
// the io.Reader and crypto/cipher.Stream interfaces.
type Cipher struct {
    input    [16]uint32
    output   [64]byte
    nextByte int
    rounds   int
    eof      bool
}

var _ cipher.Stream = (*Cipher)(nil)
var _ io.Reader = (*Cipher)(nil)

// New returns an initialized instance of a new ChaCha cipher. A ChaCha
// key is 32 bytes and a ChaCha IV is 8 bytes, so len(key) must be >= 32
// and len(iv) must be >= 8. Rounds should be one of 8, 12, or 20.
func New(key, iv []byte, rounds int) *Cipher {
    c := new(Cipher)
    c.input[0] = 0x61707865 // "expand 32-byte k"
    c.input[1] = 0x3320646e //
    c.input[2] = 0x79622d32 //
    c.input[3] = 0x6b206574 //
    c.input[4] = binary.LittleEndian.Uint32(key[0:])
    c.input[5] = binary.LittleEndian.Uint32(key[4:])
    c.input[6] = binary.LittleEndian.Uint32(key[8:])
    c.input[7] = binary.LittleEndian.Uint32(key[12:])
    c.input[8] = binary.LittleEndian.Uint32(key[16:])
    c.input[9] = binary.LittleEndian.Uint32(key[20:])
    c.input[10] = binary.LittleEndian.Uint32(key[24:])
    c.input[11] = binary.LittleEndian.Uint32(key[28:])
    c.input[14] = binary.LittleEndian.Uint32(iv[0:])
    c.input[15] = binary.LittleEndian.Uint32(iv[4:])
    c.rounds = rounds
    c.nextByte = len(c.output)
    return c
}

// Fills the output field with the next block and sets nextByte accordingly.
func (c *Cipher) next() error {
    var t uint32
    if c.eof {
        return errors.New("exhausted keystream")
    }
    a := c.input[0]
    b := c.input[1]
    c1 := c.input[2]
    d := c.input[3]
    e := c.input[4]
    f := c.input[5]
    g := c.input[6]
    h := c.input[7]
    i := c.input[8]
    j := c.input[9]
    k := c.input[10]
    l := c.input[11]
    m := c.input[12]
    n := c.input[13]
    o := c.input[14]
    p := c.input[15]

    for z := c.rounds; z > 0; z -= 2 {
        a += e
        t = m ^ a
        m = (t << 16) | (t >> (32 - 16))
        i += m
        t = e ^ i
        e = (t << 12) | (t >> (32 - 12))
        a += e
        t = m ^ a
        m = (t << 8) | (t >> (32 - 8))
        i += m
        t = e ^ i
        e = (t << 7) | (t >> (32 - 7))

        b += f
        t = n ^ b
        n = (t << 16) | (t >> (32 - 16))
        j += n
        t = f ^ j
        f = (t << 12) | (t >> (32 - 12))
        b += f
        t = n ^ b
        n = (t << 8) | (t >> (32 - 8))
        j += n
        t = f ^ j
        f = (t << 7) | (t >> (32 - 7))

        c1 += g
        t = o ^ c1
        o = (t << 16) | (t >> (32 - 16))
        k += o
        t = g ^ k
        g = (t << 12) | (t >> (32 - 12))
        c1 += g
        t = o ^ c1
        o = (t << 8) | (t >> (32 - 8))
        k += o
        t = g ^ k
        g = (t << 7) | (t >> (32 - 7))

        d += h
        t = p ^ d
        p = (t << 16) | (t >> (32 - 16))
        l += p
        t = h ^ l
        h = (t << 12) | (t >> (32 - 12))
        d += h
        t = p ^ d
        p = (t << 8) | (t >> (32 - 8))
        l += p
        t = h ^ l
        h = (t << 7) | (t >> (32 - 7))

        a += f
        t = p ^ a
        p = (t << 16) | (t >> (32 - 16))
        k += p
        t = f ^ k
        f = (t << 12) | (t >> (32 - 12))
        a += f
        t = p ^ a
        p = (t << 8) | (t >> (32 - 8))
        k += p
        t = f ^ k
        f = (t << 7) | (t >> (32 - 7))

        b += g
        t = m ^ b
        m = (t << 16) | (t >> (32 - 16))
        l += m
        t = g ^ l
        g = (t << 12) | (t >> (32 - 12))
        b += g
        t = m ^ b
        m = (t << 8) | (t >> (32 - 8))
        l += m
        t = g ^ l
        g = (t << 7) | (t >> (32 - 7))

        c1 += h
        t = n ^ c1
        n = (t << 16) | (t >> (32 - 16))
        i += n
        t = h ^ i
        h = (t << 12) | (t >> (32 - 12))
        c1 += h
        t = n ^ c1
        n = (t << 8) | (t >> (32 - 8))
        i += n
        t = h ^ i
        h = (t << 7) | (t >> (32 - 7))

        d += e
        t = o ^ d
        o = (t << 16) | (t >> (32 - 16))
        j += o
        t = e ^ j
        e = (t << 12) | (t >> (32 - 12))
        d += e
        t = o ^ d
        o = (t << 8) | (t >> (32 - 8))
        j += o
        t = e ^ j
        e = (t << 7) | (t >> (32 - 7))
    }

    a += c.input[0]
    binary.LittleEndian.PutUint32(c.output[4*0:], a)
    b += c.input[1]
    binary.LittleEndian.PutUint32(c.output[4*1:], b)
    c1 += c.input[2]
    binary.LittleEndian.PutUint32(c.output[4*2:], c1)
    d += c.input[3]
    binary.LittleEndian.PutUint32(c.output[4*3:], d)
    e += c.input[4]
    binary.LittleEndian.PutUint32(c.output[4*4:], e)
    f += c.input[5]
    binary.LittleEndian.PutUint32(c.output[4*5:], f)
    g += c.input[6]
    binary.LittleEndian.PutUint32(c.output[4*6:], g)
    h += c.input[7]
    binary.LittleEndian.PutUint32(c.output[4*7:], h)
    i += c.input[8]
    binary.LittleEndian.PutUint32(c.output[4*8:], i)
    j += c.input[9]
    binary.LittleEndian.PutUint32(c.output[4*9:], j)
    k += c.input[10]
    binary.LittleEndian.PutUint32(c.output[4*10:], k)
    l += c.input[11]
    binary.LittleEndian.PutUint32(c.output[4*11:], l)
    m += c.input[12]
    binary.LittleEndian.PutUint32(c.output[4*12:], m)
    n += c.input[13]
    binary.LittleEndian.PutUint32(c.output[4*13:], n)
    o += c.input[14]
    binary.LittleEndian.PutUint32(c.output[4*14:], o)
    p += c.input[15]
    binary.LittleEndian.PutUint32(c.output[4*15:], p)

    // Update block counter
    ctr := (uint64(c.input[13])<<32 | uint64(c.input[12])) + 1
    if ctr == 0 {
        c.eof = true
    }
    c.input[12] = uint32(ctr)
    c.input[13] = uint32(ctr >> 32)

    c.nextByte = 0
    return nil
}

// Seek sets the cipher's internal stream position to the nth 64-byte
// block. For example, Seek(0) sets the cipher back to its initial
// state.
func (c *Cipher) Seek(n uint64) {
    c.input[12] = uint32(n)
    c.input[13] = uint32(n >> 32)
    c.eof = false
    c.next() // always succeeds
}

// Read implements io.Reader.Read(). After 2^70 bytes of output the
// keystream will be exhausted and this function will return the io.EOF
// error. There are no other error conditions.
func (c *Cipher) Read(p []byte) (int, error) {
    n := 0
    for ; n < len(p); n++ {
        if c.nextByte >= len(c.output) {
            if err := c.next(); err != nil {
                return n, io.EOF
            }
        }
        p[n] = c.output[c.nextByte]
        c.nextByte++
    }
    return n, nil
}

// XORKeyStream implements crypto/cipher.Cipher. It will panic when the
// keystream has been exhausted.
func (c *Cipher) XORKeyStream(dst, src []byte) {
    for i := 0; i < len(dst); i++ {
        if c.nextByte >= len(c.output) {
            if err := c.next(); err != nil {
                panic(err)
            }
        }
        dst[i] = src[i] ^ c.output[c.nextByte]
        c.nextByte++
    }
}

package main

import (
    "crypto/rand"
    "encoding/binary"
    "math"
)

// secureIntn возвращает случайное целое число в диапазоне [0, n) с использованием crypto/rand.
func secureIntn(n int) int {
    if n <= 0 {
        return 0
    }
    var v uint64
    // Генерируем 64-битное число, пока не попадёт в нужный диапазон без смещения
    limit := math.MaxUint64 - (math.MaxUint64 % uint64(n))
    for {
        if err := binary.Read(rand.Reader, binary.BigEndian, &v); err != nil {
            // при ошибке возвращаем 0 – но ошибка крайне маловероятна
            return 0
        }
        if v < limit {
            break
        }
    }
    return int(v % uint64(n))
}

// secureString генерирует случайную строку заданной длины из заданного алфавита.
func secureString(alphabet string, length int) string {
    if length <= 0 || len(alphabet) == 0 {
        return ""
    }
    b := make([]byte, length)
    alphabetLen := len(alphabet)
    for i := range b {
        b[i] = alphabet[secureIntn(alphabetLen)]
    }
    return string(b)
}
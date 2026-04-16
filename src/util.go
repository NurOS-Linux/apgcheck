// SPDX-FileCopyrightText: m1lkydev, AnmiTaliDev
// SPDX-License-Identifier: GPL-3.0-or-later

package checker

import (
	"fmt"
	"math/rand"
	"time"
)

func GenerateRandomNumber() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	num := ""
	for i := 0; i < 8; i++ {
		digit := r.Intn(10)
		num += fmt.Sprint(digit)
	}
	return num
}

func IsEmpty[T comparable](value T) bool {
	var zero T
	return value == zero
}

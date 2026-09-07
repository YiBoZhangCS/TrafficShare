package quota

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const DecimalGB int64 = 1_000_000_000

func Remaining(limit, used int64) int64 {
	if limit <= used {
		return 0
	}
	return limit - used
}

func Exhausted(limit, used int64) bool {
	return limit <= 0 || used >= limit
}

func ParseGB(text string) (int64, error) {
	text = strings.TrimSpace(strings.TrimSuffix(strings.ToUpper(text), "GB"))
	if text == "" {
		return 0, errors.New("quota is empty")
	}
	parts := strings.Split(text, ".")
	if len(parts) > 2 {
		return 0, errors.New("invalid quota")
	}
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || whole < 0 {
		return 0, errors.New("invalid quota")
	}
	bytes := whole * DecimalGB
	if len(parts) == 2 {
		if len(parts[1]) > 9 {
			return 0, errors.New("quota has more than 9 decimal places")
		}
		fraction := parts[1] + strings.Repeat("0", 9-len(parts[1]))
		v, err := strconv.ParseInt(fraction, 10, 64)
		if err != nil {
			return 0, errors.New("invalid quota")
		}
		bytes += v
	}
	if bytes <= 0 {
		return 0, errors.New("quota must be positive")
	}
	return bytes, nil
}

func FormatGB(bytes int64) string {
	if bytes < 0 {
		bytes = 0
	}
	return fmt.Sprintf("%.2f GB", float64(bytes)/float64(DecimalGB))
}

package output

import (
	"encoding/csv"
	"io"
)

// RenderCSV renders data as CSV to the given writer
// headers: column headers
// rows: data rows (each row is a slice of string values)
func RenderCSV(w io.Writer, headers []string, rows [][]string) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write headers
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Write data rows
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return writer.Error()
}

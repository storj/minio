package cmd

import (
	"fmt"
	pathutil "path"
	"runtime"
	"strings"
)

func getSource(n int) string {
	var funcName string
	pc, filename, lineNum, ok := runtime.Caller(n)
	if ok {
		filename = pathutil.Base(filename)
		funcName = strings.TrimPrefix(runtime.FuncForPC(pc).Name(),
			"github.com/storj/minio/cmd.")
	} else {
		filename = "<unknown>"
		lineNum = 0
	}

	return fmt.Sprintf("[%s:%d:%s()]", filename, lineNum, funcName)
}

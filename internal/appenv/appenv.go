package appenv

import (
	"bufio"
	"log"
	"os"
	"strings"
)

var (
	isProd      = false
	isStag      = false
	isLocal     = false
	EnvName     = ""
	envFilePath = os.Getenv("ENV_FILE_PATH")
)

func init() {
	file, err := os.Open(envFilePath)
	if err != nil {
		pwd, _ := os.Getwd()
		log.Fatalf("error: can not read .env file, pwd=%s ,env path=%s, err=%v", pwd, envFilePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, val, ok := strings.Cut(line, "=")
		if !ok || line[0] == '#' {
			continue
		}

		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		// escape quotes if any
		var q byte = '"'
		lastIndex := len(val) - 1
		if val[0] == q && val[lastIndex] == q {
			val = val[1:lastIndex]
		}

		err := os.Setenv(key, val)
		if err != nil {
			log.Fatal("can not set env var error: ", err)
		}
	}

	appEnv := os.Getenv("APP_ENV")
	switch appEnv {
	case "local":
		isLocal = true
	case "stag":
		isStag = true
	case "prod":
		isProd = true
	default:
		log.Fatal("The value for APP_ENV in the .env file not determined, aborting...")
	}

	EnvName = appEnv
}

func IsProd() bool {
	return isProd
}
func IsStag() bool {
	return isStag
}
func IsLocal() bool {
	return isLocal
}

func IsStagOrLocal() bool {
	return IsStag() || IsLocal()
}

func IsProdOrStag() bool {
	return IsProd() || IsStag()
}

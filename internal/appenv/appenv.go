package appenv

import (
	"log"
	"os"
)

var (
	isProd  = false
	isStag  = false
	isLocal = false
	EnvName = ""
)

func init() {
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

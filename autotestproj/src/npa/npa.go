package npa

/*
#cgo CFLAGS: -I. -I/home/ych/zr9101/install/npa/lib/include/
#cgo LDFLAGS:-L/home/ych/zr9101/install/npa/lib/ -lstdc++ -lc -lpthread -ldl -lnpa
#include "platform.h"
#include "NpaLib.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "SncpServer.h"
#include "common.h"
*/
import "C"

import (
	"fmt"
)

func Npa_init() int {
	fmt.Printf("Cm_NicIsOnLine = %d\n", C.Cm_NicIsOnLine())
	return 0
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type ArchName string

const (
	ARM    ArchName = "ARM"
	METAPC ArchName = "metapc"
)

type TaskArch struct {
	Arch    ArchName
	Bit     int
	Version string
}

func GetOBPOScriptPath() string {
	path := os.Getenv("OBPO_PATH")
	if path != "" {
		return path
	}
	panic("Cannot found OBPO_PATH.")
}

func getArchBinary(arch TaskArch) string {
	if arch.Arch == ARM {
		if arch.Bit == 32 {
			return filepath.Join(arch.Version, "main_arm.idb")
		} else {
			return filepath.Join(arch.Version, "main_arm64.i64")
		}
	} else if arch.Arch == METAPC {
		if arch.Bit == 32 {
			return filepath.Join(arch.Version, "main_x86.idb")
		} else {
			return filepath.Join(arch.Version, "main_x86_64.i64")
		}
	}
	return ""
}

func copy(src string, dest string) error {
	bytesRead, err := ioutil.ReadFile(src)

	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dest, bytesRead, 0644)

	return err
}

func RunOBPO(requestJson string) (response string) {
	taskArch := TaskArch{}
	err := json.Unmarshal([]byte(requestJson), &taskArch)
	if err != nil {
		return err.Error()
	}
	binary := getArchBinary(taskArch)
	if binary == "" {
		return "-1"
	}
	tmpDir, err := ioutil.TempDir("", "obpo")
	if err != nil {
		println("Create tmpdir error: " + err.Error())
		return "-2"
	}

	fmt.Println("TEMP: " + tmpDir)
	binaryPath := filepath.Join(tmpDir, "binary")
	if taskArch.Bit == 64 {
		binaryPath += ".i64"
	} else {
		binaryPath += ".idb"
	}
	err = copy(binary, binaryPath)
	if err != nil {
		println("Copy binary error: " + err.Error())
		return "-3"
	}

	scriptPath := filepath.Join(tmpDir, "ida_script.py")
	err = copy(GetOBPOScriptPath(), scriptPath)
	if err != nil {
		println("Copy script error: " + err.Error())
		return "-4"
	}

	jsonPath := filepath.Join(tmpDir, "task.json")
	err = ioutil.WriteFile(jsonPath, []byte(requestJson), 0555)
	if err != nil {
		println("Write task error: " + err.Error())
		return "-5"
	}

	idaPath := filepath.Join(taskArch.Version, "idapro", "ida.exe")
	if taskArch.Bit == 64 {
		idaPath = filepath.Join(taskArch.Version, "idapro", "ida64.exe")
	}

	ctxt, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctxt, idaPath, "-A", fmt.Sprintf("-S%s %s", scriptPath, jsonPath), binaryPath)
	_ = append(cmd.Env, fmt.Sprintf("JSON_PATH=%s", jsonPath))
	err = cmd.Run()
	if err != nil && err.Error() != "exit status 1" {
		println("Command error: " + err.Error())
	}

	resultPath := filepath.Join(tmpDir, "result")
	content, err := os.ReadFile(resultPath)
	if err != nil {
		println("Read result error: " + err.Error())
		return "-7"
	}

	_ = os.RemoveAll(tmpDir)
	return string(content)
}

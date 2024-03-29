package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

type ArchName string

const (
	ARM    ArchName = "ARM"
	METAPC ArchName = "metapc"
)

const errorsPath = "errors"

func init() {
	err := os.Mkdir(errorsPath, 0555)
	if err != nil {
		fmt.Println(err.Error())
	}
}

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
	path = "obpo_script.py"
	_, err := os.Stat(path)
	if os.IsExist(err) {
		return path
	}
	panic("Cannot found OBPO_PATH.")
}

func GetOBPOTimeout() int {
	env := os.Getenv("OBPO_TIMEOUT")
	if env != "" {
		timeout, err := strconv.Atoi(env)
		if err == nil {
			return timeout
		}
	}
	return 60
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

func fileCopy(src string, dest string) error {
	bytesRead, err := ioutil.ReadFile(src)

	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dest, bytesRead, 0644)

	return err
}

func makeErrorResponse(code int, error string) Response {
	return Response{
		Code:  code,
		Error: error,
		Warn:  "",
		Data:  ResultData{},
	}
}

func prepareIdb(dir string, arch TaskArch) (string, error) {
	binary := getArchBinary(arch)
	_, err := os.Stat(binary)
	if binary == "" || err != nil {
		return "", errors.New(
			fmt.Sprintf("unsupported current hexrays version(%s) or architecture(%s:%d), "+
				"please see: github.com/obpo-project/obpo-plugin", arch.Version, arch.Arch, arch.Bit))
	}

	idbPath := filepath.Join(dir, "binary")
	if arch.Bit == 64 {
		idbPath += ".i64"
	} else {
		idbPath += ".idb"
	}
	err = fileCopy(binary, idbPath)
	if err != nil {
		println("Copy binary error: " + err.Error())
		return "", errors.New("server internal error")
	}
	return idbPath, err
}

func prepareObpo(dir string) (string, error) {
	scriptPath := filepath.Join(dir, "obpo_script.py")
	err := fileCopy(GetOBPOScriptPath(), scriptPath)
	if err != nil {
		println("Copy script error: " + err.Error())
		return "", errors.New("server internal error")
	}
	return scriptPath, err
}

func prepareTask(dir string, request string) (string, error) {
	taskPath := filepath.Join(dir, "task.json")
	err := ioutil.WriteFile(taskPath, []byte(request), 0555)
	if err != nil {
		println("Write task error: " + err.Error())
		return "", errors.New("server internal error")
	}
	return taskPath, err
}

func startTask(arch TaskArch, inputFile string, obpoPath string, taskPath string) error {
	idaPath := filepath.Join(arch.Version, "idapro", "ida.exe")
	if arch.Bit == 64 {
		idaPath = filepath.Join(arch.Version, "idapro", "ida64.exe")
	}

	ctxt, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(GetOBPOTimeout()))
	defer cancel()
	cmd := exec.CommandContext(ctxt, idaPath, "-A", fmt.Sprintf("-S%s %s", obpoPath, taskPath), inputFile)
	_ = append(cmd.Env, fmt.Sprintf("JSON_PATH=%s", taskPath))
	err := cmd.Run()
	if ctxt.Err() == context.DeadlineExceeded {
		return errors.New("process timeout")
	}
	if err != nil && err.Error() != "exit status 1" {
		println("Command error: " + err.Error())
		return errors.New("obpo except exit")
	}
	return nil
}

func fileContent(path string) string {
	bytesRead, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(bytesRead)
}

func makeResponse(dir string, err error) Response {
	errorMsg := fileContent(filepath.Join(dir, "error"))
	warnMsg := fileContent(filepath.Join(dir, "warn"))
	mba := fileContent(filepath.Join(dir, "mba"))
	code := 0
	if mba == "" {
		code = -6
	}
	if err != nil {
		errorMsg = err.Error() + "\n" + errorMsg
	}
	return Response{
		Code:  code,
		Error: errorMsg,
		Warn:  warnMsg,
		Data:  ResultData{Mba: mba},
	}

}

func process(requestJson string) (response Response) {
	taskArch := TaskArch{}
	err := json.Unmarshal([]byte(requestJson), &taskArch)
	if err != nil {
		return makeErrorResponse(-1, "Unable to unmarshal request.")
	}

	tmpDir, err := ioutil.TempDir("", "obpo")
	if err != nil {
		println("Create tmpdir error: " + err.Error())
		return makeErrorResponse(-2, "Server internal error.")
	}

	defer func() {
		_ = os.RemoveAll(tmpDir)
		if response.Code == 0 || len(requestJson) > 1024*1024*2 {
			return
		}

		id := time.Now().Unix()
		path := filepath.Join(errorsPath, fmt.Sprintf("%d_%d.json", response.Code, id))
		_ = ioutil.WriteFile(path, []byte(requestJson), 0555)

		path = filepath.Join(errorsPath, fmt.Sprintf("%d_%d.err", response.Code, id))
		_ = ioutil.WriteFile(path, []byte(response.Error), 0555)
	}()

	idbPath, err := prepareIdb(tmpDir, taskArch)
	if err != nil {
		return makeErrorResponse(-3, err.Error())
	}

	obpoPath, err := prepareObpo(tmpDir)
	if err != nil {
		return makeErrorResponse(-4, err.Error())
	}

	taskPath, err := prepareTask(tmpDir, requestJson)
	if err != nil {
		return makeErrorResponse(-5, err.Error())
	}

	err = startTask(taskArch, idbPath, obpoPath, taskPath)

	return makeResponse(tmpDir, err)
}

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	logFile    = "/var/log/zclock-update.log"
	statusFile = "/var/run/zclock-update.status"
)

func logMsg(msg string) {
	entry := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	fmt.Print(entry)

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		_, _ = f.WriteString(entry)
	}
}

func setStatus(status string) {
	_ = os.WriteFile(statusFile, []byte(status+"\n"), 0644)
}

func runCmd(name string, args ...string) error {
	logMsg(fmt.Sprintf("Running: %s %s", name, strings.Join(args, " ")))
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		logMsg(string(output))
	}
	return err
}

func installPackage(debPath string) {
	if _, err := os.Stat(debPath); os.IsNotExist(err) {
		logMsg(fmt.Sprintf("ERROR: Package %s not found", debPath))
		setStatus("ERROR: File not found")
		os.Exit(1)
	}

	setStatus("UPDATING")
	logMsg(fmt.Sprintf("=== ZclockID Package Update Initiated for: %s ===", debPath))

	// Verify with dpkg-deb
	infoCmd := exec.Command("dpkg-deb", "-I", debPath)
	infoOut, err := infoCmd.CombinedOutput()
	if err != nil {
		logMsg(fmt.Sprintf("ERROR: Corrupted deb package: %v\n%s", err, string(infoOut)))
		setStatus("ERROR: Invalid debian package")
		os.Exit(1)
	}

	// Install package
	if err := runCmd("dpkg", "-i", debPath); err != nil {
		logMsg("dpkg reported missing dependencies, running apt-get install -f -y...")
		if err := runCmd("apt-get", "install", "-f", "-y"); err != nil {
			logMsg(fmt.Sprintf("ERROR: Package installation failed: %v", err))
			setStatus("ERROR: Install failed")
			os.Exit(1)
		}
	}

	// Reload systemd and restart services
	_ = runCmd("systemctl", "daemon-reload")
	_ = runCmd("systemctl", "restart", "zclock-api.service")

	setStatus("SUCCESS")
	logMsg("=== ZclockID Package Update Completed Successfully ===")
}

func runRecovery() {
	logMsg("=== Starting ZclockID Appliance Emergency Recovery ===")

	// 1. Verify /zclockid hierarchy
	dirs := []string{
		"/zclockid/config/samba",
		"/zclockid/config/freeradius",
		"/zclockid/config/bind",
		"/zclockid/config/chrony",
		"/zclockid/config/overrides.d",
		"/zclockid/data",
		"/zclockid/logs",
		"/zclockid/api",
		"/zclockid/daemons",
	}
	for _, d := range dirs {
		_ = os.MkdirAll(d, 0755)
	}

	// 2. Sysvol Option A link
	if _, err := os.Stat("/var/lib/samba/sysvol"); err == nil {
		sysvolLink := "/zclockid/data/sysvol"
		_ = os.Remove(sysvolLink)
		_ = os.Symlink("/var/lib/samba/sysvol", sysvolLink)
		logMsg("Verified Sysvol Option A symlink: /zclockid/data/sysvol -> /var/lib/samba/sysvol")
	}

	// 3. Permissions
	_ = runCmd("chown", "-R", "root:root", "/zclockid")
	_ = runCmd("chmod", "755", "/zclockid", "/zclockid/config", "/zclockid/api")
	_ = runCmd("chmod", "-R", "700", "/zclockid/data", "/zclockid/logs")

	// 4. Restart Core Services
	services := []string{"samba-ad-dc", "bind9", "freeradius", "chrony", "zclock-api", "nginx"}
	for _, s := range services {
		logMsg(fmt.Sprintf("Restarting service: %s", s))
		_ = runCmd("systemctl", "restart", s)
	}

	logMsg("=== Emergency Recovery Completed Successfully ===")
}

func printUsage() {
	fmt.Printf("ZclockID Recovery & Package Updater (Go Native)\n")
	fmt.Printf("Usage: %s <command> [arguments]\n\n", filepath.Base(os.Args[0]))
	fmt.Printf("Commands:\n")
	fmt.Printf("  install <file.deb>   Install or upgrade a .deb appliance package\n")
	fmt.Printf("  recover              Run emergency appliance system and permission recovery\n")
	fmt.Printf("  status               Print current update status\n")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "install":
		if len(os.Args) < 3 {
			fmt.Println("Error: path to .deb package required")
			os.Exit(1)
		}
		installPackage(os.Args[2])
	case "recover":
		runRecovery()
	case "status":
		data, err := os.ReadFile(statusFile)
		if err != nil {
			fmt.Println("Status: IDLE (no update in progress)")
		} else {
			fmt.Printf("Status: %s", string(data))
		}
	default:
		// If called with a deb path directly (backward compatibility with script call)
		if strings.HasSuffix(os.Args[1], ".deb") {
			installPackage(os.Args[1])
		} else {
			printUsage()
			os.Exit(1)
		}
	}
}


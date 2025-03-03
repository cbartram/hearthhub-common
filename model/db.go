package model

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	//Combat: veryeasy, easy, hard, veryhard
	//DeathPenalty: casual, veryeasy, easy, hard, hardcore
	//Resources: muchless, less, more, muchmore, most
	//Raids: none, muchless, less, more, muchmore
	//Portals: casual, hard, veryhard

	// Difficulties & Death penalties
	VERY_EASY = "veryeasy"
	EASY      = "easy"
	HARD      = "hard"     // only valid for portals
	VERY_HARD = "veryhard" // combat only & only valid for portals
	CASUAL    = "casual"   // only valid for portals
	HARDCORE  = "hardcore" // deathpenalty only

	// Resources & Raids
	NONE      = "none" // Raid only
	MUCH_LESS = "muchless"
	LESS      = "less"
	MORE      = "more"
	MUCHMORE  = "muchmore"
	MOST      = "most" // resource only

	// Server states
	RUNNING    = "running"
	TERMINATED = "terminated"
)

func Connect() *gorm.DB {
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN:               fmt.Sprintf("%s:%s@tcp(%s:3306)/hearthhub?charset=utf8mb4&parseTime=True&loc=Local", os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_PASSWORD"), os.Getenv("MYSQL_HOST")),
		DefaultStringSize: 256,
	}), &gorm.Config{})

	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	log.Infof("migrating database")
	err = db.AutoMigrate(
		&User{},
		&Server{},
		&BackupFile{},
		&ConfigFile{},
		&ModFile{},
		&WorldFile{},
		&WorldDetails{},
		&Modifier{},
	)

	if err != nil {
		log.Fatalf("failed to run database migrations: %v", err)
	}

	return db
}

// SubscriptionLimits stores user limits on their subscription's plan but is omitted from DB functions
type SubscriptionLimits struct {
	CpuLimit            int  `json:"cpuLimit"`
	MemoryLimit         int  `json:"memoryLimit"`
	MaxBackups          int  `json:"maxBackups"`
	MaxWorlds           int  `json:"maxWorlds"`
	ExistingWorldUpload bool `json:"existingWorldUpload"`
}

// CognitoCredentials stores user authentication data from Cognito but is omitted from DB functions
type CognitoCredentials struct {
	RefreshToken    string `json:"refresh_token,omitempty"`
	TokenExpiration int32  `json:"token_expiration_seconds,omitempty"`
	AccessToken     string `json:"access_token,omitempty"`
	IdToken         string `json:"id_token,omitempty"`
}

// Modifier represents a game world modifier with key-value pairs
type Modifier struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	WorldID     uint           `gorm:"column:world_id;index" json:"world_id"`
	Key         string         `gorm:"column:key;index" json:"key"`
	Value       string         `gorm:"column:value" json:"value"`
	CreatedAt   time.Time      `gorm:"column:created_at" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"column:updated_at" json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
	WorldDetail WorldDetails   `gorm:"foreignKey:WorldID;references:ID" json:"-"`
}

func (Modifier) TableName() string {
	return "modifiers"
}

// WorldDetails represents the nested JSON structure for server world configuration
type WorldDetails struct {
	ID                    uint           `gorm:"primaryKey" json:"id"`
	Name                  string         `gorm:"column:name;not null" json:"name"` // The name of the server
	ServerID              uint           `gorm:"column:server_id;index;not null" json:"server_id"`
	World                 string         `gorm:"column:world;not null" json:"world"` // The name of the world
	CPURequests           int            `gorm:"column:cpu_requests;not null;default:1" json:"cpu_requests"`
	MemoryRequests        int            `gorm:"column:memory_requests;not null;default:1024" json:"memory_requests"`
	Port                  string         `gorm:"column:port;not null" json:"port"`
	Password              string         `gorm:"column:password" json:"password"`
	EnableCrossplay       bool           `gorm:"column:enable_crossplay;default:false" json:"enable_crossplay"`
	Public                bool           `gorm:"column:public;default:false" json:"public"`
	InstanceID            string         `gorm:"column:instance_id" json:"instance_id"`
	SaveIntervalSeconds   int            `gorm:"column:save_interval_seconds;default:300" json:"save_interval_seconds"`
	BackupCount           int            `gorm:"column:backup_count;default:5" json:"backup_count"`
	InitialBackupSeconds  int            `gorm:"column:initial_backup_seconds;default:300" json:"initial_backup_seconds"`
	BackupIntervalSeconds int            `gorm:"column:backup_interval_seconds;default:3600" json:"backup_interval_seconds"`
	CreatedAt             time.Time      `gorm:"column:created_at" json:"created_at"`
	UpdatedAt             time.Time      `gorm:"column:updated_at" json:"updated_at"`
	DeletedAt             gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Relations
	Modifiers []Modifier `gorm:"foreignKey:WorldID" json:"modifiers,omitempty"`
}

func (c WorldDetails) ToStringArgs() string {
	var sb strings.Builder
	args := fmt.Sprintf("/valheim/valheim_server.x86_64 -name %s -port %s -world %s -password %s -instanceid %s -backups %s -backupshort %s -backuplong %s ",
		c.Name, c.Port, c.World, c.Password, c.InstanceID, strconv.Itoa(c.BackupCount), strconv.Itoa(c.InitialBackupSeconds), strconv.Itoa(c.BackupIntervalSeconds))

	if c.EnableCrossplay {
		sb.WriteString("-crossplay ")
	}

	if c.Public {
		sb.WriteString("-public 1 ")
	} else {
		sb.WriteString("-public 0 ")
	}

	for _, modifier := range c.Modifiers {
		sb.WriteString(fmt.Sprintf("-modifier %s %s ", modifier.Key, modifier.Value))
	}

	// Write the logs to a shared mount on the pvc so that the sidecar can tail these looking
	// for the join code.
	sb.WriteString("-logFile /valheim/BepInEx/config/server-logs.txt")
	return args + sb.String()
}

func (WorldDetails) TableName() string {
	return "world_details"
}

// User represents a user of the system
type User struct {
	ID                 uint               `gorm:"primaryKey" json:"id"`
	DiscordUsername    string             `gorm:"column:discord_username" json:"discordUsername,omitempty"`
	Email              string             `gorm:"column:email" json:"email,omitempty"`
	AvatarId           string             `gorm:"column:avatar_id" json:"avatarId"`
	DiscordID          string             `gorm:"column:discord_id;uniqueIndex" json:"discordId,omitempty"`
	CustomerId         string             `gorm:"column:customer_id" json:"customerId,omitempty"`
	SubscriptionId     string             `gorm:"column:subscription_id" json:"subscriptionId"`
	SubscriptionLimits SubscriptionLimits `gorm:"-" json:"subscriptionLimits,omitempty"`
	SubscriptionStatus string             `gorm:"-" json:"subscriptionStatus,omitempty"`
	Credentials        CognitoCredentials `gorm:"-" json:"credentials,omitempty"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
	DeletedAt          gorm.DeletedAt     `gorm:"index" json:"deleted_at,omitempty"`

	// Relations
	Servers     []Server     `gorm:"foreignKey:UserID" json:"servers"`
	ModFiles    []ModFile    `gorm:"foreignKey:UserID" json:"mod_files"`
	ConfigFiles []ConfigFile `gorm:"foreignKey:UserID" json:"config_files"`
	BackupFiles []BackupFile `gorm:"foreignKey:UserID" json:"backup_files"`
	WorldFiles  []WorldFile  `gorm:"foreignKey:UserID" json:"world_files"`
}

func GetUser(discordId string, db *gorm.DB) (*User, error) {
	var user User
	tx := db.Preload("Servers").
		Preload("ModFiles").
		Preload("ConfigFiles").
		Preload("BackupFiles").
		Preload("WorldFiles").
		Where("discord_id = ?", discordId).
		First(&user)

	if tx.Error != nil {
		return nil, tx.Error
	}

	return &user, nil
}

func (User) TableName() string {
	return "users"
}

// Server represents a Valheim game server
type Server struct {
	ID             uint           `gorm:"primaryKey" json:"id"`
	UserID         uint           `gorm:"column:user_id;index" json:"user_id"`
	ServerIP       string         `gorm:"column:server_ip" json:"server_ip"`
	ServerPort     int            `gorm:"column:server_port" json:"server_port"`
	ServerMemory   int            `gorm:"column:server_memory" json:"server_memory"`
	ServerCPU      int            `gorm:"column:server_cpu" json:"server_cpu"`
	CPULimit       int            `gorm:"column:cpu_limit" json:"cpu_limit"`
	MemoryLimit    int            `gorm:"column:memory_limit" json:"memory_limit"`
	PVCName        string         `gorm:"column:pvc_name" json:"pvc_name"`
	DeploymentName string         `gorm:"column:deployment_name" json:"deployment_name"`
	State          string         `gorm:"column:state" json:"state"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Relations
	User         User         `gorm:"foreignKey:UserID" json:"-"`
	WorldDetails WorldDetails `gorm:"foreignKey:ServerID;references:ID" json:"world_details"`
	WorldFiles   []WorldFile  `gorm:"foreignKey:ServerID" json:"world_files,omitempty"`
}

func (Server) TableName() string {
	return "servers"
}

// BaseFile contains common fields for all file types
type BaseFile struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	UserID    uint           `gorm:"column:user_id;index" json:"user_id"`
	FileName  string         `gorm:"column:file_name;uniqueIndex:idx_file_user" json:"file_name"`
	Installed bool           `gorm:"column:installed" json:"installed"`
	S3Key     string         `gorm:"column:s3_key" json:"s3_key"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Relations
	User User `gorm:"foreignKey:UserID;references:ID" json:"-"`
}

// BackupFile represents a server backup file
type BackupFile struct {
	BaseFile
}

func (BackupFile) TableName() string {
	return "backup_files"
}

// ConfigFile represents a server configuration file
type ConfigFile struct {
	BaseFile
}

func (ConfigFile) TableName() string {
	return "config_files"
}

// ModFile represents a server mod .zip archive
type ModFile struct {
	BaseFile
	UpVotes            int       `gorm:"column:upvotes" json:"upvotes"`
	Downloads          int       `gorm:"column:downloads" json:"downloads"`
	OriginalUploadDate time.Time `gorm:"column:original_upload_date" json:"original_upload_date"`
	LatestUploadDate   time.Time `gorm:"column:latest_upload_date" json:"latest_upload_date"`
	Creator            string    `json:"creator"`
	HeroImage          string    `json:"hero_image"`
	Description        string    `json:"description"`
}

func (ModFile) TableName() string {
	return "mod_files"
}

// WorldFile represents a world save file (which is not a backup).
type WorldFile struct {
	BaseFile
	ServerID uint `gorm:"column:server_id;index" json:"server_id"`

	// Relations
	Server Server `gorm:"foreignKey:ServerID" json:"-"`
}

func (WorldFile) TableName() string {
	return "world_files"
}

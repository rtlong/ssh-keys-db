package main

import (
	"bytes"
	"crypto/md5"
	// "crypto/sha1"
	// "crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	kingpin "gopkg.in/alecthomas/kingpin.v1"
	"os"
	// "os/exec"
	"regexp"
	// "strconv"
	"strings"
	"time"
)

type KeysDB []*Key
type KeyFingerprint struct {
	Digest string
	Length int
	Type   string
}
type Key struct {
	Fingerprint *KeyFingerprint
	Uses        []*KeyUse
}

type KeyUse struct {
	Type        string
	Name        string
	Description string     `json:",omitempty"`
	Since       *time.Time `json:",omitempty"`
}

var (
	VERSION    string
	BUILD_DATE string

	filepath         *string = new(string)
	queryFingerprint *string = new(string)
	usageType        *string = new(string)
	usageName        *string = new(string)
	usageDescription *string = new(string)
	usageSinceRaw    *string = new(string)
)

func Version() string {
	return fmt.Sprintf("%s - built %s", VERSION, BUILD_DATE)
}

func initKingpin() {
	var cmd *kingpin.CmdClause

	kingpin.Version(Version())

	cmd = kingpin.Command("query", "Look up public key by fingerprint as argument or by private/public key path or via stdin")
	cmd.Flag("file", "path to public or private key file to add").ExistingFileVar(filepath)
	cmd.Flag("fingerprint", "fingerprint of SSH public key").StringVar(queryFingerprint)
	cmd = kingpin.Command("record", "Record usage of public key")
	cmd.Flag("file", "path to public or private key file to add").Required().ExistingFileVar(filepath)
	cmd.Flag("type", "usage type").Required().EnumVar(&usageType, "github-user", "github-repo", "aws-ec2-keypair", "rightscale-user", "rightscale-credential", "rightscale-key", "server-login")
	cmd.Flag("name", "type-specific name").Required().StringVar(usageName)
	cmd.Flag("description", "type-specific description").StringVar(usageDescription)
	cmd.Flag("since", "date/time when this use of this key started").StringVar(usageSinceRaw)
}

func dbFilepath() string {
	filepath := os.Getenv("SSH_KEYS_DB")
	if filepath == "" {
		panic("You must set SSH_KEYS_DB")
	}
	return filepath
}
func loadDB(filepath string) *KeysDB {
	file, err := os.OpenFile(filepath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		panic(fmt.Sprintf("Couldn't open file %s", file))
	}
	defer file.Close()

	json_decoder := json.NewDecoder(file)

	var db = new(KeysDB)
	json_decoder.Decode(db)
	return db
}

func saveDB(filepath string, db *KeysDB) {
	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(fmt.Sprintf("Couldn't open file %s", file))
	}
	defer file.Close()

	marshaled, err := json.Marshal(db)
	if err != nil {
		panic(err)
	}
	var out bytes.Buffer
	json.Indent(&out, marshaled, "", "\t")
	out.WriteTo(file)
	file.WriteString("\n")
}

var sshKeyTypePattern = regexp.MustCompile(`dsa|dss|rsa`)

func normalizeSshKeyType(keyType string) string {
	match := sshKeyTypePattern.FindString(keyType)
	if match == "" {
		panic("SSH key type doesn't match pattern")
	}
	return strings.ToUpper(match)
}

func fingerprintKeyFileNative(filepath string) *KeyFingerprint {
	var buf bytes.Buffer
	file, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	_, err = buf.ReadFrom(file)
	if err != nil {
		panic(err)
	}

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(buf.Bytes())
	if err != nil {
		panic(err)
	}

	md5sum := md5.Sum(pubkey.Marshal())

	return &KeyFingerprint{
		Digest: ColonDelimitedHex(md5sum[:]),
		Type:   normalizeSshKeyType(pubkey.Type()),
		Length: determinePubkeyLength(pubkey),
	}
}

func determinePubkeyLength(pubkey ssh.PublicKey) int {
	// fields := DeserializePubkey(pubkey.Marshal())
	// modulus := fields[2]
	// fmt.Printf("len(pubkey.modulus) = %#v\n", len(modulus))
	return 0
}

func DeserializePubkey(pubkey []byte) (fields [][]byte) {
	var cStart, cEnd uint32
	var length uint32
	for cStart < uint32(len(pubkey)) {
		cEnd += 4
		length = binary.BigEndian.Uint32(pubkey[cStart:cEnd])
		cStart = cEnd
		cEnd += length
		fields = append(fields, pubkey[cStart:cEnd])
		cStart = cEnd
	}
	return
}

func ColonDelimitedHex(data []byte) string {
	var out []string
	for _, b := range data {
		out = append(out, fmt.Sprintf("%02x", b))
	}
	return strings.Join(out, ":")
}

var SshkeygenFingerprintPattern = regexp.MustCompile(`\A(\d+) ((?:[0-9a-f]{2}:)+[0-9a-f]{2})\s+.+?\s+\((\w+)\)\s*\z`)

// func fingerprintKeyFileExt(filepath string) *KeyFingerprint {
// 	var err error
// 	cmd := exec.Command("ssh-keygen", "-E", "md5", "-lf", filepath)

// 	output, err := cmd.CombinedOutput()
// 	if _, ok := err.(*exec.ExitError); ok {
// 		fmt.Println(string(output))
// 		panic(err)
// 	} else if err != nil {
// 		panic(err)
// 	}

// 	matches := SshkeygenFingerprintPattern.FindSubmatch(output)
// 	if matches == nil {
// 		panic(fmt.Sprintf("ssh-keygen output didn't match pattern!\n%s", output))
// 	}

// 	length, err := strconv.Atoi(string(matches[1]))
// 	if err != nil {
// 		panic(fmt.Sprintf("Couldn't parse key length as int: %s", matches[1]))
// 	}

// 	return &KeyFingerprint{
// 		Length: length,
// 		Digest: string(matches[2]),
// 		Type:   string(matches[3]),
// 	}
// }

func (k *Key) AddUse(newUse *KeyUse) {
	for _, existingUse := range k.Uses {
		if existingUse.Type == newUse.Type && existingUse.Name == newUse.Name {
			if newUse.Description != "" {
				existingUse.Description = newUse.Description
			}
			if newUse.Since != nil && !(*newUse.Since).IsZero() {
				existingUse.Since = newUse.Since
			}
			return
		}
	}
	k.Uses = append(k.Uses, newUse)
}

func (db *KeysDB) LookupKey(digestQuery string) (*Key, bool) {
	for _, key := range *db {
		if key.Fingerprint.Digest == digestQuery {
			return key, true
		}
	}

	return &Key{}, false
}

func (db *KeysDB) CreateKey(f *KeyFingerprint) *Key {
	var newKey = Key{Fingerprint: f}
	*db = append(*db, &newKey)
	return &newKey
}

func (db *KeysDB) FindOrCreateKey(f *KeyFingerprint) *Key {
	var key *Key
	key, ok := db.LookupKey(f.Digest)
	if !ok {
		key = db.CreateKey(f)
	}
	return key
}

type Lookup struct {
	DigestQuery string
	Key         *Key   `json:",omitempty"`
	Error       string `json:",omitempty"`
}

func main() {
	initKingpin()

	switch kingpin.Parse() {
	case "record":
		fingerprint := fingerprintKeyFileNative(*filepath)
		db := loadDB(dbFilepath())
		key := db.FindOrCreateKey(fingerprint)

		var usageSince *time.Time
		if *usageSinceRaw != "" {
			t, err := time.Parse(time.RFC3339, *usageSinceRaw)
			if err != nil {
				panic(err)
			}
			usageSince = &t
		}

		key.AddUse(&KeyUse{Type: *usageType, Name: *usageName, Description: *usageDescription, Since: usageSince})
		saveDB(dbFilepath(), db)

		marshaled, err := json.Marshal(key)
		if err != nil {
			panic(err)
		}
		var out bytes.Buffer
		json.Indent(&out, marshaled, "", "\t")
		out.WriteTo(os.Stdout)

	case "query":
		if *queryFingerprint == "" {
			fingerprint := fingerprintKeyFileNative(*filepath)
			queryFingerprint = &fingerprint.Digest
		}

		db := loadDB(dbFilepath())

		lookup := Lookup{DigestQuery: *queryFingerprint}
		key, ok := db.LookupKey(*queryFingerprint)
		if ok {
			lookup.Key = key
		} else {
			lookup.Error = "key not found"
			defer os.Exit(1)
		}

		marshaled, err := json.Marshal(lookup)
		if err != nil {
			panic(err)
		}
		var out bytes.Buffer
		json.Indent(&out, marshaled, "", "\t")
		out.WriteTo(os.Stdout)
	}
}

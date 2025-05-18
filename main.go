package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/logging"
)

const (
	host = "localhost"
	port = "23234"
)

type allowedUser struct {
	Name         string
	PublicKey    string
	Repo         string
	Quota        int // In Gigabytes
	IsAppendOnly bool
}

var allowedUsers []allowedUser
var userMutex sync.RWMutex

func loadUsers() bool {
	err := loadAuthorizedKeys("/home/borgwarehouse/.ssh/authorized_keys")
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func getUserByName(name string, constantTime bool) (allowedUser, bool) {
	userMutex.RLock()
	defer userMutex.RUnlock()

	for _, user := range allowedUsers {
		if constantTime {
			if subtle.ConstantTimeCompare([]byte(user.Name), []byte(name)) == 1 {
				return user, true
			}
		} else {
			if user.Name == name {
				return user, true
			}
		}
	}
	return allowedUser{}, false
}

func main() {
	s, err := wish.NewServer(
		wish.WithAddress(net.JoinHostPort(host, port)),
		// The SSH server need its own keys, this will create a keypair in the
		// given path if it doesn't exist yet.
		// By default, it will create an ED25519 key.
		wish.WithHostKeyPath(".ssh/id_ed25519"),
		wish.WithPublicKeyAuth(func(context ssh.Context, key ssh.PublicKey) bool {
			ok := loadUsers()
			if !ok {
				return false
			}

			user, ok := getUserByName(context.User(), true)
			if !ok {
				// No user found with name provided
				return false
			}
			parsed, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(user.PublicKey))
			// Returns true if the public key matches
			return ssh.KeysEqual(key, parsed) && subtle.ConstantTimeCompare(key.Marshal(), parsed.Marshal()) == 1
		}),

		wish.WithMiddleware(
			logging.Middleware(),
			func(next ssh.Handler) ssh.Handler {
				return func(sess ssh.Session) {
					user, ok := getUserByName(sess.Context().User(), false)
					if !ok {
						_ = sess.Exit(1)
						return
					}
					cmdStr := sess.RawCommand()
					if !strings.HasPrefix(cmdStr, "borg serve") {
						_ = sess.Exit(1)
						return
					}
					borgArgs := []string{"serve",
						"--storage-quota", strconv.Itoa(user.Quota) + "G",
						"--restrict-to-path", user.Repo}
					if user.IsAppendOnly {
						borgArgs = append(borgArgs, "--append-only")
					}
					cmd := wish.Command(sess, "borg", borgArgs...)
					if err := cmd.Run(); err != nil {
						wish.Fatalln(sess, err)
					}
				}
			},
		),
	)
	if err != nil {
		log.Error("Could not start server", "error", err)
	}

	if !loadUsers() {
		fmt.Println("Could not find any users in the file /home/borgwarehouse/.ssh/authorized_keys")
	} else {
		fmt.Println("Debug - Allowing the following users:")
		fmt.Println("")
		for _, user := range allowedUsers {
			fmt.Printf("- %s (%s) with public key %s\n", user.Name, user.Repo, user.PublicKey)
		}
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	log.Info("Starting SSH server", "host", host, "port", port)
	go func() {
		if err = s.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			log.Error("Could not start server", "error", err)
			done <- nil
		}
	}()

	<-done
	log.Info("Stopping SSH server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() { cancel() }()
	if err = s.Shutdown(ctx); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		log.Error("Could not stop server", "error", err)
	}
}

var (
	reCommand      = regexp.MustCompile(`command="([^"]+)"`)
	reRestrictPath = regexp.MustCompile(`--restrict-to-path\s+([^\s]+)`)
	reQuota        = regexp.MustCompile(`--storage-quota\s+(\d+)G`)
	reAppendOnly   = regexp.MustCompile(`--append-only\b`)
	reFullKey      = regexp.MustCompile(`\b(ssh-[a-z0-9-]+ [A-Za-z0-9+/=]+)\b`)
)

func loadAuthorizedKeys(path string) error {
	userMutex.Lock()
	defer userMutex.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys: %w", err)
	}
	defer file.Close()

	var users []allowedUser
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var user allowedUser

		// Extract command="..."
		cmdMatch := reCommand.FindStringSubmatch(line)
		if len(cmdMatch) < 2 {
			continue
		}
		command := cmdMatch[1]

		// Extract repo path and username from --restrict-to-path
		if m := reRestrictPath.FindStringSubmatch(command); len(m) == 2 {
			user.Repo = m[1]
			user.Name = filepath.Base(user.Repo)
		}

		// Extract quota
		if m := reQuota.FindStringSubmatch(command); len(m) == 2 {
			gb, err := strconv.Atoi(m[1])
			if err != nil {
				return fmt.Errorf("invalid quota in line: %s", line)
			}
			user.Quota = gb
		}

		// Check for append-only
		user.IsAppendOnly = reAppendOnly.MatchString(command)

		// Extract full public key
		if m := reFullKey.FindStringSubmatch(line); len(m) == 2 {
			user.PublicKey = m[1]
		}

		if user.PublicKey != "" && user.Repo != "" {
			users = append(users, user)
		}
	}

	if err = scanner.Err(); err != nil {
		return fmt.Errorf("error reading authorized_keys: %w", err)
	}
	allowedUsers = users
	return nil
}

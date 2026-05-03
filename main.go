package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"password-manager/crypto"
	"password-manager/storage"

	"github.com/google/uuid"
	"golang.org/x/term"
)

type PasswordManager struct {
	crypto  *crypto.CryptoManager
	storage *storage.Storage
}

func NewPasswordManager(masterPassword, filepath string) (*PasswordManager, error) {
	cm, err := crypto.NewCryptoManager(masterPassword)
	if err != nil {
		return nil, err
	}

	return &PasswordManager{
		crypto:  cm,
		storage: storage.NewStorage(filepath),
	}, nil
}

func readPasswordSecure() (string, error) {
	fmt.Print("Введите мастер-пароль: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(password), nil
}

func (pm *PasswordManager) Initialize(masterPassword string) error {
	hash, salt, err := crypto.HashMasterPassword(masterPassword)
	if err != nil {
		return err
	}

	data := &storage.SafeData{
		MasterHash: hash,
		MasterSalt: salt,
		Passwords:  []storage.PasswordEntry{},
		Version:    1,
	}

	return pm.storage.Save(data)
}

func (pm *PasswordManager) AddPassword(note, password string) error {
	data, err := pm.storage.Load()
	if err != nil {
		return err
	}

	encrypted, err := pm.crypto.Encrypt(password)
	if err != nil {
		return err
	}

	encryptedJSON, err := json.Marshal(encrypted)
	if err != nil {
		return err
	}

	entry := storage.PasswordEntry{
		ID:        uuid.New().String(),
		Note:      note,
		Data:      string(encryptedJSON),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	data.Passwords = append(data.Passwords, entry)
	return pm.storage.Save(data)
}

func (pm *PasswordManager) ListPasswords() error {
	data, err := pm.storage.Load()
	if err != nil {
		return err
	}

	if len(data.Passwords) == 0 {
		fmt.Println("Нет сохраненных паролей")
		return nil
	}

	fmt.Println("\n=== Сохраненные пароли ===")
	for i, entry := range data.Passwords {
		fmt.Printf("%d. Заметка: %s (ID: %s, Создан: %s)\n",
			i+1, entry.Note, entry.ID[:8], entry.CreatedAt.Format("02.01.2006 15:04"))
	}
	return nil
}

func (pm *PasswordManager) GetPassword(id string) error {
	data, err := pm.storage.Load()
	if err != nil {
		return err
	}

	for _, entry := range data.Passwords {
		if strings.HasPrefix(entry.ID, id) {
			var encrypted crypto.EncryptedData
			if err := json.Unmarshal([]byte(entry.Data), &encrypted); err != nil {
				return err
			}

			password, err := pm.crypto.Decrypt(&encrypted)
			if err != nil {
				return err
			}

			fmt.Printf("\n=== Пароль для заметки '%s' ===\n", entry.Note)
			fmt.Printf("Пароль: %s\n", password)
			fmt.Printf("Создан: %s\n", entry.CreatedAt.Format("02.01.2006 15:04"))
			return nil
		}
	}

	return fmt.Errorf("пароль с ID %s не найден", id)
}

func (pm *PasswordManager) DeletePassword(id string) error {
	data, err := pm.storage.Load()
	if err != nil {
		return err
	}

	for i, entry := range data.Passwords {
		if strings.HasPrefix(entry.ID, id) {
			data.Passwords = append(data.Passwords[:i], data.Passwords[i+1:]...)
			return pm.storage.Save(data)
		}
	}

	return fmt.Errorf("пароль с ID %s не найден", id)
}

func main() {
	filepath := "passwords.safe"

	_, err := os.Stat(filepath)
	isNew := os.IsNotExist(err)

	masterPassword, err := readPasswordSecure()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка чтения пароля: %v\n", err)
		os.Exit(1)
	}

	pm, err := NewPasswordManager(masterPassword, filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка создания менеджера: %v\n", err)
		os.Exit(1)
	}

	if isNew {
		fmt.Println("Создание нового хранилища...")
		if err := pm.Initialize(masterPassword); err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка инициализации: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Хранилище успешно создано!")
	} else {
		data, err := pm.storage.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка загрузки: %v\n", err)
			os.Exit(1)
		}

		if !crypto.VerifyMasterPassword(masterPassword, data.MasterHash, data.MasterSalt) {
			fmt.Println("Неверный мастер-пароль!")
			os.Exit(1)
		}
		fmt.Println("Доступ разрешен!")
	}

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\n=== Менеджер паролей ===")
		fmt.Println("1. Добавить пароль")
		fmt.Println("2. Показать все заметки")
		fmt.Println("3. Получить пароль")
		fmt.Println("4. Удалить пароль")
		fmt.Println("5. Выход")
		fmt.Print("Выберите действие: ")

		scanner.Scan()
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			fmt.Print("Введите заметку для пароля: ")
			scanner.Scan()
			note := strings.TrimSpace(scanner.Text())

			fmt.Print("Введите пароль для сохранения: ")
			passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка чтения: %v\n", err)
				continue
			}
			fmt.Println()
			password := string(passwordBytes)

			if password == "" {
				fmt.Println("Пароль не может быть пустым")
				continue
			}

			if err := pm.AddPassword(note, password); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка сохранения: %v\n", err)
				continue
			}

			for i := range passwordBytes {
				passwordBytes[i] = 0
			}

			fmt.Println("Пароль успешно сохранен!")

		case "2":
			if err := pm.ListPasswords(); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			}

		case "3":
			fmt.Print("Введите ID пароля: ")
			scanner.Scan()
			id := strings.TrimSpace(scanner.Text())

			if err := pm.GetPassword(id); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			}

		case "4":
			fmt.Print("Введите ID пароля для удаления: ")
			scanner.Scan()
			id := strings.TrimSpace(scanner.Text())

			if err := pm.DeletePassword(id); err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			} else {
				fmt.Println("Пароль удален!")
			}

		case "5":
			fmt.Println("До свидания!")
			return

		default:
			fmt.Println("Неверный выбор")
		}
	}
}

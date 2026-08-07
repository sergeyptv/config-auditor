package filecheck

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sergeyptv/config-auditor/internal/model"
)

const (
	groupWritableRuleID = "FS001"
	worldWritableRuleID = "FS002"
	groupReadableRuleID = "FS003"
	worldReadableRuleID = "FS004"
)

func CheckPermissions(path string) ([]model.Issue, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect configuration file %q: %w", path, err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("configuration path %q is not a regular file", path)
	}

	cleanPath := filepath.Clean(path)
	permissions := info.Mode().Perm()

	var issues []model.Issue

	issues = append(issues, checkWritePermissions(cleanPath, permissions)...)
	issues = append(issues, checkReadPermissions(cleanPath, permissions)...)

	model.SortIssues(issues)

	return issues, nil
}

func checkWritePermissions(path string, permissions os.FileMode) []model.Issue {
	if permissions&0o002 != 0 {
		return []model.Issue{
			{
				RuleID:         worldWritableRuleID,
				Severity:       model.SeverityHigh,
				Source:         path,
				Message:        fmt.Sprintf("Файл конфигурации доступен для записи всем пользователям; права: %04o", permissions),
				Recommendation: "Запретите запись остальным пользователям, например с помощью chmod o-w, и оставьте только необходимые права",
			},
		}
	}

	if permissions&0o020 != 0 {
		return []model.Issue{
			{
				RuleID:         groupWritableRuleID,
				Severity:       model.SeverityMedium,
				Source:         path,
				Message:        fmt.Sprintf("Файл конфигурации доступен для записи группе; права: %04o", permissions),
				Recommendation: "Уберите право записи у группы, если оно не требуется, например с помощью chmod g-w",
			},
		}
	}

	return nil
}

func checkReadPermissions(path string, permissions os.FileMode) []model.Issue {
	if permissions&0o004 != 0 {
		return []model.Issue{
			{
				RuleID:         worldReadableRuleID,
				Severity:       model.SeverityMedium,
				Source:         path,
				Message:        fmt.Sprintf("Файл конфигурации доступен для чтения всем пользователям; права: %04o", permissions),
				Recommendation: "Ограничьте чтение файла владельцем или доверенной группой, например установите права 0600 или 0640",
			},
		}
	}

	if permissions&0o040 != 0 {
		return []model.Issue{
			{
				RuleID:         groupReadableRuleID,
				Severity:       model.SeverityLow,
				Source:         path,
				Message:        fmt.Sprintf("Файл конфигурации доступен для чтения группе; права: %04o", permissions),
				Recommendation: "Убедитесь, что все участники группы должны иметь доступ к конфигурации; для приватного файла используйте права 0600",
			},
		}
	}

	return nil
}

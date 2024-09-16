package disconcierge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"gorm.io/gorm"
	"log/slog"
	"strings"
)

var (
	// UserFeedbackGood indicates a positive response from the user.
	UserFeedbackGood FeedbackButtonType = "G"

	// UserFeedbackOutdated indicates that the information provided is outdated.
	UserFeedbackOutdated FeedbackButtonType = "T"

	// UserFeedbackHallucinated indicates that the response contains inaccurate
	// or fabricated information.
	UserFeedbackHallucinated FeedbackButtonType = "H"

	// UserFeedbackOther indicates other types of feedback not covered by the above categories.
	UserFeedbackOther FeedbackButtonType = "O"
)

var feedbackTypeDescription = map[FeedbackButtonType]string{
	UserFeedbackGood:         "Good",
	UserFeedbackOutdated:     "Outdated",
	UserFeedbackHallucinated: "Inaccurate",
	UserFeedbackOther:        "Other",
}

// FeedbackButtonType represents the type of feedback button used in Discord interactions.
//
// It is used to identify different categories of user feedback for ChatCommand responses.
// Each type corresponds to a specific button in the Discord user interface and is associated
// with a particular feedback action.
type FeedbackButtonType string

// UserFeedback tracks [ChatCommand] user feedback, created when a user
// selects a discord message button component (these are edited into an
// interaction response when the bot responds with the OpenAI Assistant's
// response).
//
// Fields:
//   - ChatCommandID: The ID of the associated ChatCommand, indexed and not nullable.
//   - UserID: The ID of the user providing the feedback, indexed and not nullable.
//   - CustomID: A custom identifier for the feedback.
//   - Type: The type of feedback.
//   - Description: A brief description of the feedback.
//   - Detail: Detailed information about the feedback.
type UserFeedback struct {
	ModelUintID
	ModelUnixTime

	// The ID of the associated ChatCommand.
	ChatCommandID *uint `json:"chat_command_id" gorm:"index;not null"`

	// The ID of the user providing the feedback.
	UserID *string `json:"user_id" gorm:"index;not null"`

	// The value of [ChatCommand.CustomID].
	CustomID string `json:"custom_id" gorm:"type:string"`

	// The 'short' string representation of FeedbackButtonType (ex "G" for [UserFeedbackGood])
	Type string `json:"type" gorm:"type:string"`

	// The 'long' string representation of FeedbackButtonType (ex "Good" for [UserFeedbackGood])
	Description string `json:"description" gorm:"type:string"`

	// User-entered detail when using [UserFeedbackOther] (which opens a modal for
	// user text input, rather than immediately triggering the report).
	Detail string `json:"detail" gorm:"type:string"`
}

func (UserFeedback) TableName() string {
	return "user_feedback"
}

type feedbackContent struct {
	ChatCommand *ChatCommand
	CustomID    CustomID
	Report      string
}

// CustomID represents a decoded `custom_id` discord button component
// field. It contains the type of button the ID is associated with,
// and ID set to match with [ChatCommand.CustomID]
type CustomID struct {
	ReportType FeedbackButtonType
	ID         string
}

func (c CustomID) String() string {
	return fmt.Sprintf("%s:%s", c.ReportType, c.ID)
}

func (c CustomID) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("report_type", string(c.ReportType)),
		slog.String(
			"report_description",
			feedbackTypeDescription[c.ReportType],
		),
		slog.String("custom_id", c.ID),
	)
}

// decodeCustomID accepts a `custom_id` value that's been set in
// a discord button component, and decodes it into a `CustomID` struct,
// which indicates the type of button the ID is associated with,
// and the ID set to match with [ChatCommand.CustomID]
func decodeCustomID(customID string) (CustomID, error) {
	parts := strings.Split(customID, ":")
	if len(parts) != 2 {
		return CustomID{}, fmt.Errorf("invalid custom_id format")
	}

	return CustomID{
		ReportType: FeedbackButtonType(parts[0]),
		ID:         parts[1],
	}, nil
}

// getFeedbackTextInput returns text input content from a discord interaction modal
func getFeedbackTextInput(
	db *gorm.DB,
	modalData discordgo.ModalSubmitInteractionData,
) (*feedbackContent, error) {
	if modalData.CustomID != feedbackModalCustomID {
		return nil, fmt.Errorf(
			"invalid custom ID, does not match default modal ID: %s",
			modalData.CustomID,
		)
	}
	textInput := getTextInputFromInteraction(modalData)
	if textInput == nil {
		return nil, fmt.Errorf("unable to find text input component")
	}
	customID, err := decodeCustomID(textInput.CustomID)
	if err != nil {
		return nil, err
	}
	var discordMessage ChatCommand
	err = db.Where(
		"custom_id = ?", customID.ID,
	).Omit("User").Last(&discordMessage).Error
	if err != nil {
		return &feedbackContent{
			Report:   textInput.Value,
			CustomID: customID,
		}, err
	}
	return &feedbackContent{
		ChatCommand: &discordMessage,
		Report:      textInput.Value,
		CustomID:    customID,
	}, nil
}

// getTextInputFromInteraction returns the text input component from a discord interaction modal
func getTextInputFromInteraction(
	modalData discordgo.ModalSubmitInteractionData,
) *discordgo.TextInput {
	for _, component := range modalData.Components {
		if component.Type() != discordgo.ActionsRowComponent {
			continue
		}
		actionsRow, ok := component.(*discordgo.ActionsRow)
		if !ok {
			continue
		}
		for _, rowComponent := range actionsRow.Components {
			if rowComponent.Type() != discordgo.TextInputComponent {
				continue
			}
			textInput, ok := rowComponent.(*discordgo.TextInput)
			if ok {
				return textInput
			}
		}
	}
	return nil
}

// generateRandomHexString creates a random hexadecimal string of the specified length.
//
// The function generates a random byte slice and converts it to a hexadecimal string.
// If the provided length is odd, it's incremented by 1 to ensure a valid byte slice length.
//
// Parameters:
//   - length: The desired length of the hexadecimal string. If odd, it will be incremented by 1.
//
// Returns:
//   - string: The generated random hexadecimal string.
//   - error: An error if the random number generation fails, nil otherwise.
//
// Example:
//
//	hexString, err := generateRandomHexString(16)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(hexString) // Outputs a random 16-character hexadecimal string
func generateRandomHexString(length int) (string, error) {
	if length%2 != 0 {
		length++
	}
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	hexString := hex.EncodeToString(bytes)
	return hexString, nil
}

func GetFeedbackCounts(
	ctx context.Context,
	db *gorm.DB,
	chatCommandID uint,
) (map[FeedbackButtonType]int64, error) {
	feedbackCounts := make(map[FeedbackButtonType]int64)
	// Query for counts of UserFeedback records for each FeedbackButtonType
	var results []struct {
		Type  string
		Count int64
	}
	err := db.WithContext(ctx).Model(&UserFeedback{}).
		Select("type, COUNT(*) as count").
		Where("chat_command_id = ?", chatCommandID).
		Group("type").
		Find(&results).Error
	if err != nil {
		return nil, err
	}

	// Populate the map with the results
	for _, result := range results {
		feedbackCounts[FeedbackButtonType(result.Type)] = result.Count
	}
	return feedbackCounts, nil
}

func UserPreviouslySubmittedFeedback(
	ctx context.Context,
	db *gorm.DB,
	userID string,
	chatCommandID uint,
	feedbackType FeedbackButtonType,
) (bool, error) {

	err := db.WithContext(ctx).Model(&UserFeedback{}).
		Where(
			"user_id = ? AND chat_command_id = ? AND type = ?",
			userID,
			chatCommandID,
			string(feedbackType),
		).
		Take(&UserFeedback{}).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err

	}
	return true, nil
}

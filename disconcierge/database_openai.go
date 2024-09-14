package disconcierge

type OpenAICreateThread struct {
	OpenAIAPILog
}

func (OpenAICreateThread) TableName() string {
	return "openai_create_thread"
}

// OpenAIAPILog represents a log entry for an OpenAI API request and response.
// It contains information about the API call, including timestamps, request and response data,
// and any errors encountered during the API interaction.
//
// This struct is embedded in various other structs to provide a consistent
// logging structure for different types of OpenAI API calls.
//
// Fields:
//   - ModelUintID: Embedded struct providing a uint ID field.
//   - ModelUnixTime: Embedded struct providing created_at, updated_at, and deleted_at fields.
//   - ChatCommandID: Pointer to the ID of the associated ChatCommand, if any.
//   - ChatCommand: Pointer to the associated ChatCommand, if any (not stored in the database).
//   - RequestStarted: Unix timestamp (in milliseconds) when the API request started.
//   - RequestEnded: Unix timestamp (in milliseconds) when the API request ended.
//   - RequestBody: String representation of the request payload sent to the OpenAI API.
//   - ResponseBody: String representation of the response received from the OpenAI API.
//   - ResponseHeaders: String representation of the response headers received from the OpenAI API.
//   - Error: String representation of any error encountered during the API call.
//
//nolint:lll // struct tags can't be split
type OpenAIAPILog struct {
	ModelUintID
	ModelUnixTime

	ChatCommandID *uint        `json:"chat_command_id" gorm:"not null"`
	ChatCommand   *ChatCommand `json:"-" gorm:"-"`

	RequestStarted int64 `json:"request_started"`
	RequestEnded   int64 `json:"request_ended"`

	RequestBody string `json:"request_payload" gorm:"type:string"`

	ResponseBody    string `json:"response_payload" gorm:"type:string"`
	ResponseHeaders string `json:"headers" gorm:"type:string"`

	Error string `json:"error" gorm:"type:string"`
}

// OpenAICreateMessage represents a log entry for creating a message in OpenAI.
type OpenAICreateMessage struct {
	OpenAIAPILog
}

func (OpenAICreateMessage) TableName() string {
	return "openai_create_message"
}

// OpenAIListMessages represents a log entry for listing messages in OpenAI.
type OpenAIListMessages struct {
	OpenAIAPILog
}

func (OpenAIListMessages) TableName() string {
	return "openai_list_messages"
}

// OpenAICreateRun represents a log entry for creating a run in OpenAI.
type OpenAICreateRun struct {
	OpenAIAPILog
}

func (OpenAICreateRun) TableName() string {
	return "openai_create_run"
}

// OpenAIRetrieveRun represents a log entry for retrieving a run in OpenAI.
type OpenAIRetrieveRun struct {
	OpenAIAPILog
}

func (OpenAIRetrieveRun) TableName() string {
	return "openai_retrieve_run"
}

// OpenAIListRunSteps represents a log entry for listing run steps in OpenAI.
type OpenAIListRunSteps struct {
	OpenAIAPILog
}

func (OpenAIListRunSteps) TableName() string {
	return "openai_list_run_steps"
}

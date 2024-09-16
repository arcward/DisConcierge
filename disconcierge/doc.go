// Package disconcierge implements a Discord bot that integrates with OpenAI's API
// to provide intelligent responses to user queries and commands.
//
// DisConcierge is designed to handle various interactions through Discord,
// process them using OpenAI's language models, and manage user data and bot
// configurations. The bot supports features such as chat commands, private
// messaging, thread management, and user feedback collection.
//
// KeyFile components of the package include:
//
//   - DisConcierge: The main struct that encapsulates the bot's core functionality.
//   - Discord: Handles Discord integration and message processing.
//   - OpenAI: Manages interactions with the OpenAI API.
//   - API: Provides a backend API for bot management and monitoring.
//   - Database: Handles data persistence and retrieval.
//   - Queue: Manages the processing of user requests.
//
// The bot supports various commands:
//
//   - /chat: Allows users to interact with the AI in public channels.
//   - /private: Enables private conversations with the AI.
//   - /clear: Clears the conversation history for a user.
//
// DisConcierge also includes features for rate limiting, user management,
// and extensive logging to ensure smooth operation and easy troubleshooting.
//
// The package is designed to be configurable and extensible, allowing for
// easy customization of bot behavior, OpenAI integration, and Discord
// interactions.
package disconcierge

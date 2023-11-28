const r2 = require('r2')

// labels for each type of raw category given by Twitch
const chatterTypes = {
    "broadcaster": "broadcaster",
    "vips": "vip",
    "moderators": "mod",
    "staff": "staff",
    "admins": "admin",
    "global_mods": "global_mod",
    "viewers": "viewer"
}

// viewers(Name of channel) => { type, name }
async function viewers(channelName) {
    let endpoint = `https://tmi.twitch.tv/group/user/${channelName}/chatters`

    let response = await r2(endpoint).json

    let chatters = []

    // go through all types of users
    for(let chatterType in response.chatters) {
        // and each person of those types
        for(let i in response.chatters[chatterType]) {
            chatters.push({
                // use better labels for `chatterType`
                type: chatterTypes[chatterType],
                name: response.chatters[chatterType][i]
            })
        }
    }

    return chatters
}

module.exports = viewers

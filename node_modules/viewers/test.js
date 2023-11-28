const viewers = require('./')

async function logViewers(channelName) {
    console.log(await viewers(channelName))
}

// A popular 24/7 stream
logViewers('twitchplayspokemon')

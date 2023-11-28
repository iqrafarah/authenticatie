# viewers
Lists who is currently watching a given stream on Twitch

## Installation

```
npm i -s viewers
```

## Usage

Here is an example from `test.js`:
```javascript
const viewers = require('viewers')

async function logViewers(channelName) {
    console.log(await viewers(channelName))
}

// A popular 24/7 stream
logViewers('twitchplayspokemon')
```

It should output something similar to the following:
```javascript
[
    { type: 'vip', name: 'tppsimulator' },
    { type: 'mod', name: 'honshoureimu' },
    { type: 'mod', name: 'red031000' },
    { type: 'mod', name: 'rjri' },
    { type: 'mod', name: 'sinr2014' },
    { type: 'mod', name: 'tpp' },
    { type: 'viewer', name: '1in256miss' },
    { type: 'viewer', name: '20superkoopatroopa02' },
    { type: 'viewer', name: '4td0' },
    ...
]
```

Here are all of the possible types of viewers:
- `broadcaster`: The same person that is streaming
- `vip`: A status given by the streamer to special viewers
- `mod`: A status given by the streamer to moderators
- `staff`: Someone who works at Twitch
- `admin`: Someone who works at Twitch
- `global_mod`: Someone who works at Twitch
- `viewer`: An average user

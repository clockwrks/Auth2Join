import json
import aiohttp
import logging
import asyncio
from base64 import urlsafe_b64decode
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format='[38;5;9m[[0m%(asctime)s[38;5;9m][0m %(message)s[0m',
    datefmt='%H:%M:%S'
)

class Auth2Join:
    def __init__(self, guildId : str, botToken : str, clientId : str, uri : str, clientSecret : str) -> None:
        self.guildId = guildId
        self.botToken = botToken
        self.clientId = clientId
        self.redirectUri = uri
        self.clientSecret = clientSecret
        self.joinedTokens = []

    async def authorizeToken(self, token : str, session : aiohttp.ClientSession) -> Optional[str]:
        params = {
            'client_id' : str(self.clientId),
            'response_type' : 'code',
            'redirect_uri' : str(self.redirectUri),
            'scope' : 'guilds.join identify',
        }
        headers = {
            'Authorization' : token,
            'Content-Type' : 'application/json',
            'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        }
        payload = {
            'permissions' : 0,
            'authorize' : True
        }
        try:
            async with session.post('https://discord.com/api/v10/oauth2/authorize', headers = headers, params = params, json = payload, timeout = 3) as resp:
                if resp.status in [200, 201, 204]:
                    respJson = await resp.json()
                    if 'location' in respJson:
                        return respJson['location'][-30:]
                return None
        except Exception as exc:
            logging.error('Error in authorizeToken for token %s: %s' % (token, str(exc)))
            return None

    def tokenUserId(self, token : str) -> int:
        try:
            tokenParts = token.split('.')
            if not tokenParts:
                return 0
            firstPart = tokenParts[0]
            padding = '=' * ((4 - len(firstPart) % 4) % 4)
            decoded = urlsafe_b64decode(firstPart + padding)
            return int(decoded)
        except Exception as exc:
            logging.error('Error in tokenUserId for token %s: %s' % (token, str(exc)))
            return 0

    async def codeToaccessToken(self, code : str, session : aiohttp.ClientSession) -> Optional[str]:
        data = {
            'client_id' : self.clientId,
            'client_secret' : self.clientSecret,
            'grant_type' : 'authorization_code',
            'code' : code,
            'redirect_uri' : self.redirectUri
        }
        headers = {
            'Content-Type' : 'application/x-www-form-urlencoded'
        }
        try:
            async with session.post('https://discord.com/api/v10/oauth2/token', data = data, headers = headers, timeout = 3) as resp:
                if resp.status in [200, 201, 204]:
                    respJson = await resp.json()
                    if 'access_token' in respJson:
                        return respJson['access_token']
                return None
        except Exception as exc:
            logging.error('Error in codeToaccessToken for code %s: %s' % (code, str(exc)))
            return None

    async def processToken(self, rawToken : str, session : aiohttp.ClientSession) -> bool:
        token = rawToken.strip()
        if ':' in token:
            parts = token.split(':')
            token = parts[-1].strip()
        if not token:
            return False

        userId = self.tokenUserId(token)
        if userId == 0:
            logging.info('Invalid token %s' % token)
            return False

        code = await self.authorizeToken(token, session)
        if code is None:
            logging.info('Authorization failed for user %s' % userId)
            return False

        accessToken = await self.codeToaccessToken(code, session)
        if accessToken is None:
            logging.info('Access token retrieval failed for user %s' % userId)
            return False

        logging.info('Access token retrieved for user %s' % userId)
        headers = {
            'Authorization' : 'Bot %s' % self.botToken,
            'Content-Type' : 'application/json'
        }
        payload = {
            'access_token' : accessToken,
        }
        try:
            async with session.put('https://discord.com/api/v8/guilds/%s/members/%s' % (self.guildId, userId), headers = headers, json = payload, timeout = 3) as resp:
                if resp.status in [200, 201, 204]:
                    self.joinedTokens.append(token)
                    logging.info('Joined user %s' % userId)
                    return True
                else:
                    text = await resp.text()
                    logging.info('Join failed for user %s, error: %s' % (userId, text))
                    return False
        except Exception as excError:
            logging.error('Error in processToken for user %s: %s' % (userId, str(excError)))
            return False

    async def Join(self) -> None:
        try:
            with open('tokens.txt', 'r') as tokenFiles:
                tokensList = tokenFiles.readlines()
            totalTokens = len(tokensList)
            logging.info('Loaded %s tokens from tokens.txt' % totalTokens)
        except Exception as excErorr:
            logging.error('Error reading tokens.txt: %s' % str(excErorr))
            return

        addedTokens = 0
        async with aiohttp.ClientSession() as session:
            tasks = [self.processToken(token, session) for token in tokensList]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, bool) and result:
                    addedTokens += 1

        logging.info('Added %s tokens to guild %s' % (addedTokens, self.guildId))
        if self.joinedTokens:
            with open('joinedTokens.txt', 'w') as outFile:
                for token in self.joinedTokens:
                    outFile.write('%s\n' % token)

if __name__ == '__main__':
    try:
        with open('config.json', 'r') as configFile:
            config = json.load(configFile)
    except Exception as exc:
        logging.error('Error reading config.json: %s' % str(exc))
        exit(1)
    Auther = Auth2Join(guildId=config['guildId'], botToken=config['botToken'], clientId=config['clientId'], clientSecret=config['clientSecret'], uri=config['uri'])
    asyncio.run(Auther.Join())

from telethon import TelegramClient
from config import DESTINATION, API_ID, API_HASH, SESSION, CHATS, KEY_WORDS
from datetime import date, timedelta
from collections import Counter



client = TelegramClient('anon',
                    API_ID,
                    API_HASH,
                    )
# Remember to use your own values from my.telegram.org!
client = TelegramClient('anon', API_ID, API_HASH)

async def main():
        msgsum = 0
        coins = ["btc","eth","ada"]
        coinz = []
        channel = "Kucoin_Exchange"
        yesterday = date.today() - timedelta(days = 1)
    # You can print the message history of any chat:
        async for message in client.iter_messages(channel):
                try:
                        if str(yesterday) in str(message.date):
                        #       if [coin for coin in coins if(coin in message.text)]:
                                for coin in coins:
                                        if coin in message.text.split():
                                                coinz.append(coin)
                #       if "eth" in message.text:
                                                print(message.date, "-" ,message.sender.username,":", message.text)
                                                msgsum += 1
                        elif str(yesterday - timedelta(days = 1)) in str(message.date):
                                print("\nOn", yesterday, "coinz were mentioned", msgsum, "times in the group", channel, "\n")
                                break
                except Exception:
                         pass

        #print(coinz)
        counts = Counter(coinz)
        for n in coins:
                print(n, "occured", counts[n],"times.")
with client:
        client.loop.run_until_complete(main())

                                                     

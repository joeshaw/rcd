###
### Copyright 2002 Ximian, Inc.
###
### This program is free software; you can redistribute it and/or modify
### it under the terms of the GNU General Public License as published by
### the Free Software Foundation, version 2 of the License.
###
### This program is distributed in the hope that it will be useful,
### but WITHOUT ANY WARRANTY; without even the implied warranty of
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
### GNU General Public License for more details.
###
### You should have received a copy of the GNU General Public License
### along with this program; if not, write to the Free Software
### Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
###

import sys
import string

test_dict = {}
test_list = []

def register(constructor):
    obj = constructor()
    name = obj.name()

    if test_dict.has_key(name):
        sys.stderr.write("Test name collision: '" + name + "'\n")
        return

    test_dict[string.lower(name)] = constructor
    test_list.append([name, obj.keywords(), constructor])


def get_all(keyword = ""):

    instantiated_list = map(lambda x:x[-1](), test_list)

    if keyword:
        instantiated_list = filter(lambda x,k=keyword:k in x.keywords(),
                                   instantiated_list)

    instantiated_list.sort(lambda a,b:cmp(b.priority(), a.priority()))
    
    return instantiated_list


def get_random():
    if not test_list:
        sys.stderr.write("Can't get a random test: no tests registered.")
        sys.exit(0)
    item = random.choice(test_list)
    return item[-1]()


class BurnTest:

    def name(self):
        return "Unnamed!"

    def keywords(self):
        return []

    def priority(self):
        return 0

    def message(self, msg=""):
        self.log.write(msg + "\n")

    def error(self, msg):
        self.errors.append(msg)
        self.message("ERROR: " + msg)

    def test(self, rcd_server):
        self.add_fault("Test undefined for '"+self.name()+"'\n")

    def run_test(self, log, rcd_server):

        self.log = log

        name = self.name()

        self.message(">>>> Beginning test '%s'" % name)

        self.short_circuit = 0
        self.errors = []
        self.test(rcd_server)

        self.message(">>>> Test '%s' complete" % name)
        self.message()

        return self.errors
    

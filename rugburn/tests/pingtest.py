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

###
### This is a very simple example of a RugBurn test.  
###

## Test classes are derived from the BurnTest class.
class PingTest(burntest.BurnTest):

    ## Every test needs a name.  No two tests should have the
    ## same name.
    def name(self):
        return "ping"

    ## The priority related to the order that we want the
    ## tests to occur in.  If test A has a higher priority than
    ## test B, test A will be run first.  If you don't provide
    ## a 'priority' method, the test will be assigned a priority
    ## of zero.
    ##
    ## I've given 'ping' a very high priority in the hopes that
    ## it will be the first test run.  Of course, there is nothing
    ## to stop someone from writing a test with a priority of 1000001.
    def priority(self):
        return 1000000

    ## The 'test' method is does all of the actual work.
    ## The 'server' argument is the xmlrpc handle for the daemon.
    def test(self, server):

        try:
            ping = server.rcd.system.ping()
        except:
            ## If something goes wrong in our test, we signal
            ## the fault by calling the 'message' method.
            ## The text of the error will be printed out immediately.
            self.error("Can't ping server")

            ## If something goes _really_ wrong in a test, set
            ## 'short_circuit' to 1 -- this causes rugburn to
            ## not run any more tests after this one.
            self.short_circuit = 1
            return

        print ping
        if not ping \
               or not ping.has_key("name") \
               or not ping.has_key("distro_info"):
            self.error("Ping returned a malformed structure")
            self.short_circuit = 1
            return

        ## Routine communication with the user should occur via
        ## the 'message' method.
        self.message("Server: %s" % ping["name"])
        self.message("Distro: %s" % ping["distro_info"])


## We need to register every test class that we define.
## If a test isn't registered, it will never get run.
burntest.register(PingTest)

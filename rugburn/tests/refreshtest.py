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
### Refresh each channel individually.
### FIXME: Should also test rcd.packsys.refresh_all_channels
###

class RefreshTest(burntest.BurnTest):

    def name(self):
        return "refresh"

    def test(self, server):

        try:
            channels = server.rcd.packsys.get_channels()
        except:
            self.error("Couldn't get channel list")
            return

        for c in channels:
            self.message("Refreshing channel '%s' (ID %d)" % (
                c["name"], c["id"]))
            tid = server.rcd.packsys.refresh_channel(c["id"])
            polling = 1
            start = time.time()
            while polling:
                pending = server.rcd.system.poll_pending(tid)
                if not pending["is_active"]:
                    polling = 0
                elif time.time() - start > 120:
                    self.error("Refresh of '%s' (ID %s) timed out after 120s" %
                               (c["name"], c["id"]))
                else:
                    time.sleep(1)


burntest.register(RefreshTest)
        

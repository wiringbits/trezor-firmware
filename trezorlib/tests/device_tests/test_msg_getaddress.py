# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.


from trezorlib import btc, messages as proto
from trezorlib.tools import H_, parse_path

from ..support import ckd_public as bip32
from .common import TrezorTest


class TestMsgGetaddress(TrezorTest):
    def test_btc(self):
        self.setup_mnemonic_nopin_nopassphrase()
        assert (
            btc.get_address(self.client, "Bitcoin", [])
            == "1EfKbQupktEMXf4gujJ9kCFo83k1iMqwqK"
        )
        assert (
            btc.get_address(self.client, "Bitcoin", [1])
            == "1CK7SJdcb8z9HuvVft3D91HLpLC6KSsGb"
        )
        assert (
            btc.get_address(self.client, "Bitcoin", [0, H_(1)])
            == "1JVq66pzRBvqaBRFeU9SPVvg3er4ZDgoMs"
        )
        assert (
            btc.get_address(self.client, "Bitcoin", [H_(9), 0])
            == "1F4YdQdL9ZQwvcNTuy5mjyQxXkyCfMcP2P"
        )
        assert (
            btc.get_address(self.client, "Bitcoin", [0, 9999999])
            == "1GS8X3yc7ntzwGw9vXwj9wqmBWZkTFewBV"
        )

    def test_ltc(self):
        self.setup_mnemonic_nopin_nopassphrase()
        assert (
            btc.get_address(self.client, "Litecoin", [])
            == "LYtGrdDeqYUQnTkr5sHT2DKZLG7Hqg7HTK"
        )
        assert (
            btc.get_address(self.client, "Litecoin", [1])
            == "LKRGNecThFP3Q6c5fosLVA53Z2hUDb1qnE"
        )
        assert (
            btc.get_address(self.client, "Litecoin", [0, H_(1)])
            == "LcinMK8pVrAtpz7Qpc8jfWzSFsDLgLYfG6"
        )
        assert (
            btc.get_address(self.client, "Litecoin", [H_(9), 0])
            == "LZHVtcwAEDf1BR4d67551zUijyLUpDF9EX"
        )
        assert (
            btc.get_address(self.client, "Litecoin", [0, 9999999])
            == "Laf5nGHSCT94C5dK6fw2RxuXPiw2ZuRR9S"
        )

    def test_tbtc(self):
        self.setup_mnemonic_nopin_nopassphrase()
        assert (
            btc.get_address(self.client, "Testnet", [111, 42])
            == "moN6aN6NP1KWgnPSqzrrRPvx2x1UtZJssa"
        )

    def test_bch(self):
        self.setup_mnemonic_allallall()
        assert (
            btc.get_address(self.client, "Bcash", parse_path("44'/145'/0'/0/0"))
            == "bitcoincash:qr08q88p9etk89wgv05nwlrkm4l0urz4cyl36hh9sv"
        )
        assert (
            btc.get_address(self.client, "Bcash", parse_path("44'/145'/0'/0/1"))
            == "bitcoincash:qr23ajjfd9wd73l87j642puf8cad20lfmqdgwvpat4"
        )
        assert (
            btc.get_address(self.client, "Bcash", parse_path("44'/145'/0'/1/0"))
            == "bitcoincash:qzc5q87w069lzg7g3gzx0c8dz83mn7l02scej5aluw"
        )

    def test_bch_multisig(self):
        self.setup_mnemonic_allallall()
        xpubs = []
        for n in map(
            lambda index: btc.get_public_node(
                self.client, parse_path("44'/145'/" + str(index) + "'")
            ),
            range(1, 4),
        ):
            xpubs.append(n.xpub)

        def getmultisig(chain, nr, signatures=[b"", b"", b""], xpubs=xpubs):
            return proto.MultisigRedeemScriptType(
                pubkeys=list(
                    map(
                        lambda xpub: proto.HDNodePathType(
                            node=bip32.deserialize(xpub), address_n=[chain, nr]
                        ),
                        xpubs,
                    )
                ),
                signatures=signatures,
                m=2,
            )

        for nr in range(1, 4):
            assert (
                btc.get_address(
                    self.client,
                    "Bcash",
                    parse_path("44'/145'/" + str(nr) + "'/0/0"),
                    show_display=(nr == 1),
                    multisig=getmultisig(0, 0),
                )
                == "bitcoincash:pqguz4nqq64jhr5v3kvpq4dsjrkda75hwy86gq0qzw"
            )
            assert (
                btc.get_address(
                    self.client,
                    "Bcash",
                    parse_path("44'/145'/" + str(nr) + "'/1/0"),
                    show_display=(nr == 1),
                    multisig=getmultisig(1, 0),
                )
                == "bitcoincash:pp6kcpkhua7789g2vyj0qfkcux3yvje7euhyhltn0a"
            )

    def test_public_ckd(self):
        self.setup_mnemonic_nopin_nopassphrase()

        node = btc.get_public_node(self.client, []).node
        node_sub1 = btc.get_public_node(self.client, [1]).node
        node_sub2 = bip32.public_ckd(node, [1])

        assert node_sub1.chain_code == node_sub2.chain_code
        assert node_sub1.public_key == node_sub2.public_key

        address1 = btc.get_address(self.client, "Bitcoin", [1])
        address2 = bip32.get_address(node_sub2, 0)

        assert address2 == "1CK7SJdcb8z9HuvVft3D91HLpLC6KSsGb"
        assert address1 == address2
import time

import pytest

from trezorlib import debuglink, messages as proto

from .common import TrezorTest


@pytest.mark.skip_t1
# @pytest.mark.skip(reason="waiting for shamir load_device support")
class TestMsgRecoveryDeviceShamirDryRun(TrezorTest):
    def test_2of3_dryrun(self):
        # TODO: load device with these (or any other valid) mnemonics
        mnemonics = [
            "crush merchant academic acid dream decision orbit smug trend trust painting slice glad crunch veteran lunch friar satoshi engage aquatic",
            "crush merchant academic agency devote eyebrow disaster island deploy flip toxic budget numerous airport loyalty fitness resident learn sympathy daughter",
            "crush merchant academic always course verdict rescue paces fridge museum energy solution space ladybug junction national biology game fawn coal",
        ]
        debuglink.load_device_by_mnemonic(
            self.client,
            mnemonic=mnemonics[0:2],
            pin="",
            passphrase_protection=True,
            label="test",
            language="english",
            skip_checksum=True,
        )

        ret = self.client.call_raw(
            proto.RecoveryDevice(
                passphrase_protection=False,
                pin_protection=False,
                label="label",
                language="english",
                dry_run=True,
                type=proto.ResetDeviceBackupType.Slip39_Single_Group,
            )
        )

        # Confirm Dryrun
        assert isinstance(ret, proto.ButtonRequest)
        self.client.debug.press_yes()
        ret = self.client.call_raw(proto.ButtonAck())

        # Homescreen
        assert isinstance(ret, proto.ButtonRequest)
        self.client.debug.press_yes()
        ret = self.client.call_raw(proto.ButtonAck())

        # Enter word count
        assert ret == proto.ButtonRequest(
            code=proto.ButtonRequestType.MnemonicWordCount
        )
        self.client.debug.input(str(20))
        ret = self.client.call_raw(proto.ButtonAck())

        # Homescreen
        assert isinstance(ret, proto.ButtonRequest)
        self.client.debug.press_yes()
        ret = self.client.call_raw(proto.ButtonAck())

        # Check 2 of 3 shares
        # TODO: check all shares when #276 is implemented
        for mnemonic in mnemonics[1:3]:
            assert ret == proto.ButtonRequest(
                code=proto.ButtonRequestType.MnemonicInput
            )
            self.client.transport.write(proto.ButtonAck())
            for word in mnemonic.split(" "):
                time.sleep(1)
                self.client.debug.input(word)
            ret = self.client.transport.read()

            # Confirm success
            assert isinstance(ret, proto.ButtonRequest)
            self.client.debug.press_yes()
            ret = self.client.call_raw(proto.ButtonAck())

        # Workflow succesfully ended
        assert isinstance(ret, proto.Success)

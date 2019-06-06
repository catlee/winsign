from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
TEST_PE_FILES = list(DATA_DIR.glob("**/*.exe")) + list(DATA_DIR.glob("**/*.dll"))

TEST_MSI_FILES = list(DATA_DIR.glob("**/*.msi"))

EXPECTED_SIGNATURES = {
    DATA_DIR
    / "unsigned.exe": {
        "sha1": b"0482010026b3e9100171d6dcd4ebff504a602233e456c6b721ffd9e1603ea6a37c73a8391c0f"
        b"14301899920c1b6bd0b0c8d3b4bf4d921d8ca8f889668063291dd58c22b62fc5615a1d2cd782"
        b"ee51c1eb1335a37cd932147d2a9f4a5193dc3f1ba431a2dd7eee77be018122ed286b2d201f1a"
        b"74bbd4fd2a521f50fdeb259627d43e4b0cb7638daf9f29e4f6f530480cd5ae27486ba6b14b73"
        b"00295d79e16e32bdb0053158fa4b77c10445edd548e68ef740bac671921c0fcae7c765f583c3"
        b"2482cf2baffc68346cb213825aaa25abb30624befcbd8516c1c64af4b4c99f65fc02f36615cf"
        b"1b8f0771483b23c17a999d3ab5ecd79938c773aa4fadb3b6f45adc3df5ba6a9b",
        "sha256": b"048201007ba76e391cdc50d0ba6c7f4de9561d9fa7e07450fb0ca324041a09496768edb7b80b"
        b"4d7b23c2a59e523e7ef51bf53b87733185e48100875144f5735b7a5a50ffa58b9e4418a74273"
        b"df2dcf9874c3db80d18e791646b477fafc8a62d8ee4703b66691005cf640b5b868bd3e2c8fb1"
        b"128f43e394a7584d766e36bdeb5027d5a6c105762e7935e18a10260108ec08f0d924b8088f28"
        b"f7f26bf7026f221e810110a32718c4c06fbfc8565e1bf1df866829bc6d9a3671d760beafef95"
        b"ad47a274636e674d55225af9533ad591832f5b218f6b116807faeb2506006a67133ebd65a0b5"
        b"f57a83c5193416264c89b035efb64c7aa574ee0765a4be6bc157e0ebc7efd77a",
    }
}

import click
from click import File

from ltchiptool import Board, Family, SocInterface
from ltchiptool.models import BoardParamType
from ltchiptool.util.cli import DevicePortParamType
from ltchiptool.util.flash import FlashConnection
from ltchiptool.util.streams import ClickProgressCallback

from .image import BL60XImageError, BL60XLayout


@click.command()
@click.option(
    "--board",
    required=True,
    type=BoardParamType(),
    help="Known board flash layout to validate against",
)
@click.option(
    "--application",
    required=True,
    type=File("rb"),
    help="Application-only BL60x firmware binary",
)
@click.option(
    "-d",
    "--device",
    required=True,
    type=DevicePortParamType(),
    help="UART device already in BL60x serial flash mode",
)
@click.option("-B", "--link-baudrate", type=int)
@click.option("-b", "--baudrate", type=int)
def cli(board: Board, application, device: str, link_baudrate: int, baudrate: int):
    """Write FW slot 0 and select it without a second flash reset."""
    family = Family.get(short_name="BL60X")
    soc = SocInterface.get(family)
    soc.flash_set_connection(FlashConnection(device, baudrate, link_baudrate))
    try:
        click.echo("Connecting to BL60x serial loader...")
        soc.flash_connect()
        slot_index, slot_offset, table_offset = soc.flash_update_slot0(
            application.read(),
            BL60XLayout(
                name=board.name,
                flash_size=int(board["upload.flash_size"]),
                fw_addresses=(board.region("app")[0], board.region("ota")[0]),
                fw_capacities=(board.region("app")[1], board.region("ota")[1]),
            ),
            callback=ClickProgressCallback(),
        )
    except (BL60XImageError, OSError, RuntimeError, ValueError) as err:
        raise click.ClickException(str(err)) from err
    finally:
        soc.flash_disconnect()

    click.echo(f"Verified FW slot {slot_index} at 0x{slot_offset:06X}")
    click.echo(
        f"Selected slot {slot_index} via partition table at 0x{table_offset:06X}"
    )
    click.echo("Disconnect GPIO8 from high and reset once for normal boot.")

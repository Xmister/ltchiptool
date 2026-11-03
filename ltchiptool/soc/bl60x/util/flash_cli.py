import click
from click import File

from ltchiptool import Family, SocInterface
from ltchiptool.util.cli import DevicePortParamType
from ltchiptool.util.flash import FlashConnection
from ltchiptool.util.streams import ClickProgressCallback

from .image import BOARD_LAYOUTS, BL60XImageError


@click.command()
@click.option(
    "--board",
    required=True,
    type=click.Choice(sorted(BOARD_LAYOUTS)),
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
def cli(board: str, application, device: str, link_baudrate: int, baudrate: int):
    """Write the inactive FW slot and select it without a second flash reset."""
    family = Family.get(short_name="BL60X")
    soc = SocInterface.get(family)
    soc.flash_set_connection(FlashConnection(device, baudrate, link_baudrate))
    try:
        click.echo("Connecting to BL60x serial loader...")
        soc.flash_connect()
        slot_index, slot_offset, table_offset = soc.flash_update_inactive_slot(
            application.read(),
            BOARD_LAYOUTS[board],
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

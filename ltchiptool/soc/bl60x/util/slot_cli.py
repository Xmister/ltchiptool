from pathlib import Path

import click

from ltchiptool import Board
from ltchiptool.models import BoardParamType

from .image import BL60XImageError, make_bl60x_slot_image_from_template


@click.command()
@click.option("--board", required=True, type=BoardParamType())
@click.option(
    "--application",
    "application_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Application-only BL60x firmware binary",
)
@click.option(
    "--output",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output path for the complete BL60x slot image",
)
def cli(board: Board, application_path: Path, output_path: Path) -> None:
    """Package a BL60x slot image from its boot-header template."""
    template_path = Path(__file__).parent / board["build.boot_header"]
    try:
        slot = make_bl60x_slot_image_from_template(
            application_path.read_bytes(), template_path.read_bytes()
        )
        output_path.write_bytes(slot)
    except (BL60XImageError, OSError) as err:
        raise click.ClickException(str(err)) from err
    click.echo(f"Slot image: {output_path} ({len(slot)} bytes)")

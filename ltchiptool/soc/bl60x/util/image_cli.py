from pathlib import Path

import click

from .image import BOARD_LAYOUTS, BL60XImageError, package_bl60x_slot


@click.command()
@click.option(
    "--board",
    required=True,
    type=click.Choice(sorted(BOARD_LAYOUTS)),
    help="Known board flash layout to validate against",
)
@click.option(
    "--backup",
    "backup_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Full BL60x flash backup, including its partition table",
)
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
    help="New file for the bootinfo plus application slot image",
)
def cli(
    board: str, backup_path: Path, application_path: Path, output_path: Path
) -> None:
    """Package an application for the inactive slot in a verified BL60x backup."""
    try:
        offset, size, digest = package_bl60x_slot(
            backup_path, application_path, output_path, BOARD_LAYOUTS[board]
        )
    except (BL60XImageError, OSError) as err:
        raise click.ClickException(str(err)) from err

    click.echo(f"Slot image: {output_path} ({size} bytes)")
    click.echo(f"Flash offset: 0x{offset:06X}")
    click.echo(f"SHA-256: {digest}")
    click.echo("This is a slot image, not a complete flash dump.")



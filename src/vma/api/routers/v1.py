from os import stat
from typing import Annotated
from loguru import logger
import jwt
from fastapi import Depends, APIRouter, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone

import vma.api.models.v1 as mod_v1
import vma.helper as helper
from vma import connector as c
from vma import auth as a
from vma import nvd
from vma import osv


router = APIRouter(prefix="/api/v1")
READ_ONLY = ["read", "write", "admin"]
WRITE = ["write", "admin"]
ADMIN = ["admin"]


def is_authorized(scope: dict, teams: list, op: list, is_root: bool) -> bool:
    if is_root:
        return True

    for team in teams:
        if team not in scope or (scope[team] not in op):
            return False
    return True


async def get_teams_for_authz(scope: dict, is_root: bool) -> list:
    if is_root:
        teams = []
        for team in (await c.get_teams())["result"]:
            teams.append(team["name"])
        return teams
    return list(scope.keys())


@router.get("/products")
async def get_products(
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    res = None

    t = await get_teams_for_authz(scope=user_data.scope, is_root=user_data.root)
    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=t, op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    try:
        res = await c.get_products(teams=t)
    except Exception as e:
        logger.error(f"Error getting products: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/product/{team}/{id}")
async def get_product(
    id: str, team: str, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    prod_id = helper.validate_input(id)
    team_id = helper.validate_input(team)
    if not team_id:
        team_id = ""

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team_id], op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = None
    try:
        res = await c.get_products(teams=[team_id], id=prod_id)
    except Exception as e:
        logger.error(f"Error getting a product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.post("/product")
async def post_product(
    prod: mod_v1.Product, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    name = helper.validate_input(prod.name)
    team = helper.validate_input(prod.team)
    description = prod.description

    if not description:
        description = ""

    if not team:
        team = ""

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team], op=WRITE
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not name:
        raise HTTPException(status_code=400, detail=helper.errors["400"])

    res = None
    try:
        res = await c.insert_product(name=name, description=description, team=team)
    except Exception as e:
        logger.error(f"Error inserting product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.delete("/product")
async def product(
    prod: mod_v1.Product, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    name = helper.validate_input(prod.name)
    team = helper.validate_input(prod.team)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team], op=ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not name or not team:
        raise HTTPException(status_code=400, detail=helper.errors["400"])

    res = None
    try:
        res = await c.delete_product(id=name, team=team)
    except Exception as e:
        logger.error(f"Error inserting product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/stats")
async def stats(user_data: mod_v1.JwtData = Depends(a.validate_access_token)) -> dict:
    t = await get_teams_for_authz(is_root=user_data.root, scope=user_data.scope)
    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=t, op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    stats = None
    try:
        products = await c.get_products(teams=t)
        images = await c.get_images(teams=t)
        stats = {
            "products": len(products["result"]) if products["status"] else None,
            "images": len(images["result"]) if images["status"] else None,
        }
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return stats


@router.get("/images")
async def images(user_data: mod_v1.JwtData = Depends(a.validate_access_token)) -> dict:
    t = await get_teams_for_authz(is_root=user_data.root, scope=user_data.scope)
    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=t, op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = None
    try:
        res = await c.get_images(teams=t)
    except Exception as e:
        logger.error(f"Getting images: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.post("/image")
async def image(
    im: mod_v1.Image, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    name = helper.validate_input(im.name)
    version = helper.validate_input(im.version)
    product = helper.validate_input(im.product)
    team = helper.validate_input(im.team)

    if not team:
        team = ""

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team], op=WRITE
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not product or not name or not version:
        raise HTTPException(status_code=400, detail=helper.errors["400"])

    res = None
    try:
        res = await c.insert_image(
            name=name, version=version, product=product, team=team
        )
    except Exception as e:
        logger.error(f"Error inserting image: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


# @router.get("/image/{t}/{p}/{n}/{ver}/vuln")
# async def image_vuln(
#     t: str,
#     p: str,
#     n: str,
#     ver: str,
#     user_data: mod_v1.JwtData = Depends(a.validate_access_token),
# ) -> dict:
#     team = helper.validate_input(t)
#     name = helper.validate_input(n)
#     version = helper.validate_input(ver)
#     product = helper.validate_input(p)
#
#     if not is_authorized(
#         is_root=user_data.root, scope=user_data.scope, teams=[team], op=READ_ONLY
#     ):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
#         )
#
#     if not team or not name or not version or not product:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST, detail=helper.errors["400"]
#         )
#
#     res = None
#     try:
#         res = await c.get_image_vulnerabilities(product, name, version, team)
#         res["result"] = helper.format_vulnerability_rows(res["result"])
#     except Exception as e:
#         logger.error(f"Error getting image: {e}")
#         raise HTTPException(status_code=500, detail=helper.errors["500"])
#     return res


@router.get("/image/compare/{t}/{p}/{n}/{v1}/{v2}")
async def image_compare(
    t: str,
    p: str,
    n: str,
    v1: str,
    v2: str,
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    team = helper.validate_input(t)
    product = helper.validate_input(p)
    image = helper.validate_input(n)
    ver1 = helper.validate_input(v1)
    ver2 = helper.validate_input(v2)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team], op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not team or not product or not image or not ver1 or not ver2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=helper.errors["400"]
        )

    res = None
    try:
        comp = await c.compare_image_versions(
            product=product, image=image, version_a=ver1, version_b=ver2, team=team
        )
        comp["result"] = helper.normalize_comparison(comp["result"])
        res = comp
    except Exception as e:
        logger.error(f"Error comparing images: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/cve/{src}/{id}")
async def cve(
    src: str, id: str, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    src_val = helper.validate_input(src)
    cve_id = helper.validate_input(id)

    if not cve_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=helper.errors["400"]
        )
    res = None
    try:
        cve_id = f"%{helper.escape_like(cve_id)}%"
        if src_val == "nvd":
            res = await c.get_vulnerabilities_by_id(id=cve_id)
        elif src_val == "osv":
            res = await c.get_osv_by_ilike_id(osv_id=cve_id)
        else:
            res = {"status": False, "result": ""}
    except Exception as e:
        logger.error(f"Error getting a product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


# @router.post("/import")
# async def importer(
#     imp: mod_v1.Import, user_data: dict = Depends(a.validate_api_token)
# ) -> dict:
#     sc = helper.validate_input(imp.scanner)
#     product = helper.validate_input(imp.product)
#     image = helper.validate_input(imp.image)
#     version = helper.validate_input(imp.version)
#     team = helper.validate_input(imp.team)
#     data = imp.data
#
#     if not user_data["status"]:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
#         )
#
#     if not is_authorized(
#         is_root=user_data["result"]["root"],
#         scope=user_data["result"]["teams"],
#         teams=[team],
#         op=WRITE,
#     ):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
#         )
#
#     if not data or len(data) < 0 or not image or not version or not product or not team:
#         raise HTTPException(status_code=400, detail=helper.errors["400"])
#
#     res = None
#     try:
#         chk = await c.get_images(
#             name=image, version=version, product=product, teams=[team]
#         )
#         if not chk["status"]:
#             ins = await c.insert_image(
#                 name=image, version=version, product=product, team=team
#             )
#         res = await c.insert_image_vulnerabilities(data)
#     except Exception as e:
#         logger.error(f"Error inserting vulnerabilities: {e}")
#         raise HTTPException(status_code=500, detail=helper.errors["500"])
#     return res


@router.post("/import/sca")
async def import_vulnerabilities_sca(
    imp: mod_v1.ImportSca,
    user_data: dict = Depends(a.validate_api_token),
) -> dict:
    """
    Import vulnerability records for an image in universal SCA format.

    This endpoint accepts SCA vulnerability data in the universal format,
    storing it independently from the NVD database.
    """
    scanner = helper.validate_input(imp.scanner)
    image_name = helper.validate_input(imp.image_name)
    image_version = helper.validate_input(imp.image_version)
    product = helper.validate_input(imp.product)
    team = helper.validate_input(imp.team)
    vulnerabilities = imp.vulnerabilities

    if not user_data["status"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not is_authorized(
        is_root=user_data["result"]["root"],
        scope=user_data["result"]["teams"],
        teams=[team],
        op=WRITE,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not image_name or not image_version or not product or not team:
        raise HTTPException(status_code=400, detail=helper.errors["400"])

    if not vulnerabilities or len(vulnerabilities) == 0:
        raise HTTPException(status_code=400, detail="No vulnerabilities provided")

    res = None
    try:
        # Ensure image exists
        chk = await c.get_images(
            name=image_name, version=image_version, product=product, teams=[team]
        )
        if not chk["result"]:
            await c.insert_image(
                name=image_name, version=image_version, product=product, team=team
            )

        res = await c.insert_vulnerabilities_sca_batch(
            vulns=vulnerabilities,
            image_name=image_name,
            image_version=image_version,
            product=product,
            team=team,
            scanner=scanner,
        )

        if not res["status"]:
            raise HTTPException(status_code=500, detail=res["result"])
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error importing SCA vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/image/{t}/{p}/{n}/{ver}/vuln-sca")
async def image_vuln_sca(
    t: str,
    p: str,
    n: str,
    ver: str,
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    """
    Get SCA vulnerabilities for a specific image.

    Returns vulnerability records in universal SCA format, stored independently from NVD data.
    """
    team = helper.validate_input(t)
    name = helper.validate_input(n)
    version = helper.validate_input(ver)
    product = helper.validate_input(p)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team], op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not team or not name or not version or not product:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=helper.errors["400"]
        )

    res = None
    try:
        res = await c.get_vulnerabilities_sca_by_image(
            image_name=name,
            image_version=version,
            product=product,
            team=team,
        )
    except Exception as e:
        logger.error(f"Error getting SCA vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.post("/import/sast")
async def import_vulnerabilities_sast(
    imp: mod_v1.ImportSast,
    user_data: dict = Depends(a.validate_api_token),
) -> dict:
    """Import SAST findings (e.g. from Semgrep)."""
    scanner = helper.validate_input(imp.scanner)
    product = helper.validate_input(imp.product)
    team = helper.validate_input(imp.team)
    findings = imp.findings

    if not user_data["status"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not is_authorized(
        is_root=user_data["result"]["root"],
        scope=user_data["result"]["teams"],
        teams=[team],
        op=WRITE,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not product or not team or not scanner:
        raise HTTPException(status_code=400, detail=helper.errors["400"])

    if not findings or len(findings) == 0:
        raise HTTPException(status_code=400, detail="No findings provided")

    res = None
    try:
        # Verify product exists
        chk = await c.get_products(teams=[team], id=product)
        if not chk["result"]:
            raise HTTPException(
                status_code=400,
                detail=f"Product '{product}' not found in team '{team}'",
            )

        res = await c.insert_vulnerabilities_sast_batch(
            findings=findings,
            product=product,
            team=team,
            scanner=scanner,
        )

        if not res["status"]:
            raise HTTPException(status_code=500, detail=res["result"])
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error importing SAST findings: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/sast/{team}/{product}")
async def get_vulnerabilities_sast_product(
    team: str,
    product: str,
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    """Get SAST findings for a specific product."""
    team_val = helper.validate_input(team)
    product_val = helper.validate_input(product)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team_val], op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not team_val or not product_val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=helper.errors["400"]
        )

    res = None
    try:
        res = await c.get_vulnerabilities_sast_by_product(
            product=product_val, team=team_val
        )
    except Exception as e:
        logger.error(f"Error getting SAST findings: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/sast/{team}")
async def get_vulnerabilities_sast_team(
    team: str,
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    """Get all SAST findings for a team across all products."""
    team_val = helper.validate_input(team)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team_val], op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not team_val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=helper.errors["400"]
        )

    res = None
    try:
        res = await c.get_vulnerabilities_sast_by_team(team=team_val)
    except Exception as e:
        logger.error(f"Error getting SAST findings for team: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.delete("/sast/{team}/{product}")
async def delete_vulnerabilities_sast(
    team: str,
    product: str,
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    """Delete all SAST findings for a product."""
    team_val = helper.validate_input(team)
    product_val = helper.validate_input(product)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team_val], op=ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not team_val or not product_val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=helper.errors["400"]
        )

    res = None
    try:
        res = await c.delete_vulnerabilities_sast_by_product(
            product=product_val, team=team_val
        )
    except Exception as e:
        logger.error(f"Error deleting SAST findings: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/sast/stats/{team}")
async def sast_stats(
    team: str,
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    """Get SAST finding statistics for a team."""
    team_val = helper.validate_input(team)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team_val], op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not team_val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=helper.errors["400"]
        )

    res = None
    try:
        res = await c.get_sast_stats_by_team(team=team_val)
    except Exception as e:
        logger.error(f"Error getting SAST stats: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.delete("/product/{t}/{id}")
async def delete_product(
    t: str, id: str, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    team = helper.validate_input(t)
    prod_id = helper.validate_input(id)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team], op=ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    if not prod_id or not team:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=helper.errors["400"]
        )

    res = None
    try:
        res = await c.delete_product(id=prod_id, team=team)
    except Exception as e:
        logger.error(f"Error deleting a product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.delete("/image/{t}/{p}")
async def delete_image(
    t: str,
    p: str,
    n: str,
    ver: str | None = None,
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    team = helper.validate_input(t)
    prod_id = helper.validate_input(p)
    name = helper.validate_input(n)
    version = None
    if ver:
        version = helper.validate_input(ver)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team], op=WRITE
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = {"status": False, "result": "Could not delete the image"}
    try:
        if name and version:
            res = await c.delete_image(
                product=prod_id, name=name, version=version, team=team
            )
        elif name:
            res = await c.delete_image(product=prod_id, name=name, team=team)
    except Exception as e:
        logger.error(f"Error deleting a product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.post("/team")
async def post_team(
    team: mod_v1.Team, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[], op=ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    name = helper.validate_input(team.name)
    description = team.description

    res = None
    if not name:
        raise HTTPException(status_code=400, detail=helper.errors["400"])

    try:
        if not description:
            description = ""
        res = await c.insert_teams(name=name, description=description)
    except Exception as e:
        logger.error(f"Error inserting product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/teams")
async def get_teams(
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    t = await get_teams_for_authz(scope=user_data.scope, is_root=user_data.root)
    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=t, op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = None
    try:
        res = await c.get_teams()
    except Exception as e:
        logger.error(f"Error getting products: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/team/{name}")
async def get_team(
    name: str, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    team_name = helper.validate_input(name)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team_name], op=READ_ONLY
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = None
    try:
        res = await c.get_teams(name=team_name)
    except Exception as e:
        logger.error(f"Error getting a product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.delete("/team/{id}")
async def delete_team(
    id: str, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    team_id = helper.validate_input(id)

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=[team_id], op=ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = None
    try:
        res = await c.delete_team(id=team_id)
    except Exception as e:
        logger.error(f"Error deleting a product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.post("/user")
async def post_user(
    user: mod_v1.User, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    scopes = helper.validate_scopes(user.scopes)
    email = helper.validate_input(user.email)
    name = helper.validate_input(user.name)
    password = helper.validate_input(user.password)

    if not email or not password or not scopes:
        raise HTTPException(status_code=400, detail=helper.errors["400"])

    t = await get_teams_for_authz(scope=scopes, is_root=user_data.root)
    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=t, op=ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = None
    try:
        res = await c.insert_users(
            email=email,
            password=a.hasher.hash(password),
            name=name,
            scopes=scopes,
        )
    except Exception as e:
        logger.error(f"Error inserting user: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.patch("/user")
async def patch_user(
    user: mod_v1.UserUpdate,
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    email = helper.validate_input(user.email)

    if user_data.username != email and not user_data.root:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    name = helper.validate_input(user.name) if user.name else None
    password = (
        helper.validate_input(user.password)
        if user.password and len(user.password) > 0
        else None
    )
    scopes = helper.validate_scopes(user.scopes) if user.scopes else None

    is_root = user.root if (user_data.root and user.root) else False

    if not email:
        raise HTTPException(status_code=400, detail=helper.errors["400"])

    res = None
    try:
        hpass = None
        if password:
            hpass = a.hasher.hash(password)
        res = await c.update_users(
            email=email, password=hpass, name=name, scopes=scopes, is_root=is_root
        )
    except Exception as e:
        logger.error(f"Error inserting product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/users")
async def get_users(
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
) -> dict:
    t = await get_teams_for_authz(scope=user_data.scope, is_root=user_data.root)
    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=t, op=ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = None
    try:
        res = await c.get_users()
    except Exception as e:
        logger.error(f"Error getting products: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.get("/user/{email}")
async def get_user(
    email: str, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    user_email = helper.validate_input(email)

    if not (user_data.username == email or user_data.root):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = None
    try:
        res = await c.get_users(email=user_email)
    except Exception as e:
        logger.error(f"Error getting a product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.delete("/user/{email}")
async def delete_user(
    email: str, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    t = await get_teams_for_authz(scope=user_data.scope, is_root=user_data.root)
    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=t, op=ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = None
    try:
        user_email = helper.validate_input(email)
        res = await c.delete_user(email=user_email)
    except Exception as e:
        logger.error(f"Error deleting a product: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res


@router.post("/token")
async def token(
    response: Response, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> dict:
    cred_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    username = helper.validate_input(form_data.username)
    password = helper.validate_input(form_data.password)

    if not username or not password:
        raise cred_exception

    access_token = None

    try:
        user_data = await c.get_users_w_hpass(email=username)
        user_scope = await c.get_scope_by_user(email=username)

        if not user_data["result"] or (
            not a.hasher.verify(password, user_data["result"][0]["hpass"])
        ):
            raise cred_exception

        access_token = a.create_token(
            username=user_data["result"][0]["email"],
            scope=user_scope["result"],
            ttype="access_token",
            root=user_data["result"][0]["is_root"],
        )

        refresh_token = a.create_token(
            username=user_data["result"][0]["email"],
            scope=user_scope["result"],
            ttype="refresh_token",
            root=user_data["result"][0]["is_root"],
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=(a._expire_refresh_token * 24 * 60 * 60),
            path="/",
        )
    except Exception as e:
        logger.error(f"Failing to authenticate user {e}")
    return {"access_token": access_token, "token_type": "Bearer"}


@router.get("/refresh_token")
async def refresh(request: Request, response: Response) -> dict:
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    try:
        payload = jwt.decode(
            refresh_token, a._secret_key_refresh, algorithms=[a._algorithm]
        )

        ttype = payload["type"]
        if ttype != "refresh_token":
            logger.debug(f"/refresh_token called with an incorrect type: {ttype}")
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        if not payload["sub"] or not payload["scope"] or not payload["type"]:
            logger.debug("/refresh_token called with a missing field")
            raise HTTPException(status_code=401, detail="Invalid token payload")

        access_token = a.create_token(
            username=payload["sub"].split(":")[1],
            scope=payload["scope"],
            root=payload["root"],
            ttype="access_token",
        )

        refresh_token = a.create_token(
            username=payload["sub"].split(":")[1],
            scope=payload["scope"],
            root=payload["root"],
            ttype="refresh_token",
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=(a._expire_refresh_token * 24 * 60 * 60),
            path="/",
        )
    except Exception as e:
        logger.error(f"Error processing the request {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    return {"access_token": access_token, "token_type": "Bearer"}


@router.get("/logout")
async def logout(request: Request, response: Response) -> dict:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=0,
        path="/",
    )
    return {"status": True, "result": "User has logout"}


@router.post("/apitoken")
async def create_api_token(
    request: mod_v1.CreateTokenRequest,
    user_data: mod_v1.JwtData = Depends(a.validate_access_token),
):
    """
    Create a new API token for CLI/programmatic access.

    **Token inherits ALL permissions from the user creating it.**

    - **description**: Optional description for the token
    - **expires_days**: Days until expiration (None = no expiration)

    Returns the token ONLY ONCE - save it securely!
    """
    if not user_data.root and (request.username != user_data.username):
        raise HTTPException(status_code=401, detail="Unauthorized operation")

    res = None
    try:
        plaintext_token = a.generate_api_token()
        token_hash = a.hasher.hash(plaintext_token)
        prefix = plaintext_token[:12]

        expires_at = None
        if request.expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(
                days=request.expires_days
            )

        q = await c.insert_api_token(
            token_hash=token_hash,
            prefix=prefix,
            user_email=request.username,
            description=request.description,
            expires_at=expires_at,
        )

        if not q["status"]:
            raise HTTPException(status_code=500, detail=q["result"])

        res = {
            "status": True,
            "result": {
                "id": q["result"]["id"],
                "token": plaintext_token,  # Only returned during creation
                "prefix": prefix,
                "user_email": request.username,
                "description": request.description,
                "created_at": q["result"]["created_at"],
                "last_used_at": None,
                "expires_at": expires_at,
                "revoked": False,
            },
        }
    except Exception as e:
        logger.error(f"Error creating API token: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    return res


@router.get("/tokens/{user}")
async def list_api_tokens(
    user: str, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
):
    """
    List API tokens.

    - Regular users see only their own tokens
    - Root users can see all tokens

    Tokens are never returned in plaintext (only prefixes shown).
    """
    res = None
    user_val = helper.validate_input(user)

    if not user_data.root or (user_val != user_data.username):
        raise HTTPException(status_code=401, detail="Unauthorized operation")

    try:
        is_root = user_data.root
        q = None
        if is_root:
            q = await c.list_api_tokens(user_email=user_val)

        if not q or not q["status"]:
            logger.debug(f"No tokens found for user {user_val}")
            return {"status": False, "result": []}

        tokens = q["result"]

        res = {"status": True, "result": tokens}
    except Exception as e:
        logger.error(f"Error listing API tokens: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    return res


@router.get("/tokens/{token_id}")
async def get_api_token(
    token_id: int, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
):
    """Get details of a specific API token."""
    try:
        q = await c.get_api_token_by_id(token_id)

        if not q["status"]:
            raise HTTPException(status_code=404, detail="Token not found")

        token = q["result"]

        if token["user_email"] != user_data.username and not user_data.root:
            raise HTTPException(
                status_code=403, detail="Unauthorized to view this token"
            )

        token["token"] = None

        res = {"status": True, "result": token}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting API token: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    return res


@router.delete("/tokens/{token_id}")
async def revoke_api_token(
    token_id: int, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
):
    """
    Revoke an API token.

    - Users can revoke their own tokens
    - Root users can revoke any token
    """
    try:
        q = await c.get_api_token_by_id(token_id)
        if not q["status"]:
            raise HTTPException(status_code=404, detail="Token not found")

        token = q["result"]

        if token["user_email"] != user_data.username and not user_data.root:
            raise HTTPException(
                status_code=403, detail="Unauthorized to view this token"
            )

        q = await c.revoke_api_token(
            token_id=token_id, user_email=user_data.username, admin=user_data.root
        )

        if not q["status"]:
            raise HTTPException(status_code=404, detail=q["result"])

        res = {"status": "success", "message": "Token revoked successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error revoking API token: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    return res


@router.post("/update/{db}")
async def update_db(
    db: str, user_data: mod_v1.JwtData = Depends(a.validate_access_token)
) -> dict:
    db_val = helper.validate_input(db)

    if db_val not in ["osv", "nvd"]:
        raise HTTPException(status_code=400, detail=helper.errors["400"])

    if not is_authorized(
        is_root=user_data.root, scope=user_data.scope, teams=["admin"], op=ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=helper.errors["401"]
        )

    res = {"status": True, "result": "Action triggered"}
    try:
        if db_val == "nvd":
            await nvd.get_modified_cves()  # TODO: Use queues for this type of tasks
        elif db_val == "osv":
            await osv.get_recent()  # TODO: use queues for this type of tasks
    except Exception as e:
        logger.error(f"Error updating database {db_val}: {e}")
        raise HTTPException(status_code=500, detail=helper.errors["500"])
    return res

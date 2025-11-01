from loguru import logger
from fastapi import APIRouter, HTTPException

import vma.api.models.v1 as mod_v1
import vma.helper as helper
from vma import connector as c

router = APIRouter(prefix='/api/v1')

@router.get('/products')
async def product():
    res = None
    try:
        res = c.get_products()
    except Exception as e:
        logger.error(f"product; error getting products: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res


@router.get('/product/{id}')
async def product(id: str):
    res = None
    try:
        prod_id = helper.validate_input(id)
        res = c.get_products(prod_id)
    except Exception as e:
        logger.error(f"product; error getting a product: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res


@router.post('/product')
async def product(prod: mod_v1.Product):
    name = helper.validate_input(prod.name)
    description = prod.description
    res = None
    if not name:
        raise HTTPException(
            status_code=400,
            detail=helper.errors['400']
        )
    
    try:
        res = c.insert_product((name, description))
    except Exception as e:
        logger.error(f"products; error inserting product: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res


@router.delete('/product')
async def product(prod: mod_v1.Product):
    pass # TODO


@router.get('/stats')
async def stats():
    stats = None
    try:
        products = c.get_products()
        images = c.get_images()
        stats = {
            'products': len(products['result']) if products['status'] else None,
            'images': len(images['result']) if images['status'] else None,
        }
    except Exception as e:
        logger.error(f"/stats; error getting stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return stats


@router.get('/images')
async def images():
    res = None
    try:
        res = c.get_images(set())
    except Exception as e:
        logger.error(f"/images; getting images: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res

from typing import Mapping


@router.post('/image')
async def image(im: mod_v1.Image):
    name = helper.validate_input(im.name)
    version = helper.validate_input(im.version)
    product = helper.validate_input(im.product)

    if not product or not name or not version:
        raise HTTPException(
            status_code=400,
            detail=helper.errors['400']
        )
    res = None
    try:
        res = c.insert_image((name, version, product))
    except Exception as e:
        logger.error(f"/image; error inserting image: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res


@router.get('/image/{p}/{n}/{ver}/vuln')
async def image_vuln(p: str, n: str, ver: str):
    name = helper.validate_input(n)
    version = helper.validate_input(ver)
    product = helper.validate_input(p)

    if not product or not name or not version:
        raise HTTPException(
            status_code=400,
            detail=helper.errors['400']
        )
    res = None
    try:
        res = c.get_image_vulnerabilities(product, name, version)
        res['result'] = helper.format_vulnerability_rows(res['result'])
    except Exception as e:
        logger.error(f"/image; error getting image: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res


@router.get('/image/compare/{p}/{im}/{v1}/{v2}')
async def image_compare(p: str, im: str, v1: str, v2: str):
    product = helper.validate_input(p)
    image = helper.validate_input(im)
    ver1 = helper.validate_input(v1)
    ver2 = helper.validate_input(v2)
    res = None
    try:
        comp = c.compare_image_versions(product, image, ver1, ver2)
        comp['result'] = helper.normalize_comparison(comp['result'])
        res = comp
    except Exception as e:
        logger.error(f"/image; error comparing images: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res


@router.get('/cve/{id}')
async def cve(id: str):
    res = None
    try:
        cve_id = helper.validate_input(id)
        cve_id = f"%{helper.escape_like(cve_id)}%"
        res = c.get_vulnerabilities_by_id(cve_id)
    except Exception as e:
        logger.error(f"product; error getting a product: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res


@router.post('/import')
async def importer(imp: mod_v1.Import):
    sc = helper.validate_input(imp.scanner)
    product = helper.validate_input(imp.product)
    image = helper.validate_input(imp.image)
    version = helper.validate_input(imp.version)
    data = imp.data
    if not data or len(data) < 0:
        raise HTTPException(
            status_code=400,
            detail=helper.errors['400']
        )
    res = None
    try:
        chk = c.get_images(name=image, version=version, product=product)
        if chk['status'] != True:
            ins = c.insert_image((image, version, product))
        res = c.insert_image_vulnerabilities(data)
    except Exception as e:
        logger.error(f"import; error inserting vulnerabilities")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res


@router.delete('/product/{id}')
async def delete_product(id: str):
    res = None
    try:
        prod_id = helper.validate_input(id)
        res = c.delete_product(prod_id)
    except Exception as e:
        logger.error(f"delete_product; error deleting a product: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res


@router.delete('/image/{p}')
async def delete_product(p: str, n: str, ver: str | None = None):
    res = None
    try:
        prod_id = helper.validate_input(p)
        name = helper.validate_input(n)
        ver = helper.validate_input(ver)
        if name and ver:
            res = c.delete_image(product=prod_id, name=name, ver=ver)
        elif name:
            res = c.delete_image(product=prod_id, name=name)
    except Exception as e:
        logger.error(f"delete_product; error deleting a product: {e}")
        raise HTTPException(
            status_code=500,
            detail=helper.errors['500']
        )
    return res
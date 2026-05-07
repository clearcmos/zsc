pkgname=zsc
pkgdesc='Fast encrypted compressed archive tool (XChaCha20-Poly1305 + zstd)'
pkgver=0.1.0.r0.6938d33
pkgrel=1
arch=('x86_64')
url='https://github.com/clearcmos/zsc'
license=('MIT')
depends=(tar zstd xdg-utils)
makedepends=(git rust)
source=("$pkgname::git+ssh://git@github.com/clearcmos/zsc.git")
sha256sums=('SKIP')

pkgver() {
    cd "$pkgname"
    local cargo_ver
    cargo_ver=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
    printf "%s.r%s.%s" "$cargo_ver" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
    cd "$pkgname"
    cargo build --release --locked
}

package() {
    cd "$pkgname"
    install -Dm0755 "target/release/zsc" "$pkgdir/usr/bin/zsc"
}

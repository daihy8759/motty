// Package buildinfo names the program variant selected at build time.
package buildinfo

// ProductName is the user-visible name of this build. The dev tag changes only
// the identity; data directories and vault keys stay shared with release builds.
const ProductName = productName

// Development reports whether this binary was built with the dev tag.
const Development = development

// DockBadge is the label the build puts in the red badge macOS draws at the
// corner of the application's Dock icon. A development build marks the running
// copy this way instead of renaming the product inside its own interface; an
// empty label means no badge.
const DockBadge = dockBadge

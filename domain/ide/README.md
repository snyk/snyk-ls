# IDE Domain

In the context of the Language Server, the "IDE domain" refers to all the elements that are relevant to the IDE. E.g. 
hovers, workspaces, actions...

LSP as a protocol is not part of the IDE Domain, but rather a presentation layer on top of it. At the moment this layer is
conflating domain and presentation, this is an interim step.

The IDE domain, will typically transform the Snyk Domain into IDE constructs - and vice-versa, that then can be transformed into LSP presentational
entities.


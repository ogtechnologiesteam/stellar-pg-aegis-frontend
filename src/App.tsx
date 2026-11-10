import { lazy, Suspense, type ReactNode } from 'react'
import { createBrowserRouter, Link, RouterProvider } from 'react-router'
import { Layout } from './components/Layout'
import { EmptyState, Skeleton } from './components/ui'
import Overview from './pages/Overview'

const Projects = lazy(() => import('./pages/Projects'))
const ProjectDetail = lazy(() => import('./pages/ProjectDetail'))
const Advisories = lazy(() => import('./pages/Advisories'))
const AdvisoryDetail = lazy(() => import('./pages/AdvisoryDetail'))
const Disclose = lazy(() => import('./pages/Disclose'))
const Methodology = lazy(() => import('./pages/Methodology'))
const Glossary = lazy(() => import('./pages/Glossary'))
const GlossaryDetail = lazy(() => import('./pages/GlossaryDetail'))

const page = (el: ReactNode) => <Suspense fallback={<Skeleton className="h-96 rounded-2xl" />}>{el}</Suspense>

const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { index: true, element: <Overview /> },
      { path: 'projects', element: page(<Projects />) },
      { path: 'projects/:id', element: page(<ProjectDetail />) },
      { path: 'advisories', element: page(<Advisories />) },
      { path: 'advisories/:id', element: page(<AdvisoryDetail />) },
      { path: 'disclose', element: page(<Disclose />) },
      { path: 'methodology', element: page(<Methodology />) },
      { path: 'glossary', element: page(<Glossary />) },
      { path: 'glossary/:slug', element: page(<GlossaryDetail />) },
      {
        path: '*',
        element: (
          <div className="card">
            <EmptyState title="Page not found" description="The page you are looking for does not exist." />
            <div className="pb-8 text-center">
              <Link to="/" className="btn-ghost">
                Back to overview
              </Link>
            </div>
          </div>
        ),
      },
    ],
  },
])

export default function App() {
  return <RouterProvider router={router} />
}

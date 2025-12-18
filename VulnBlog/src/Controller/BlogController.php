<?php

namespace App\Controller;

use App\Entity\Comment;
use App\Entity\Post;
use App\Repository\CommentRepository;
use App\Repository\PostRepository;
use App\Services\Analytics;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;

class BlogController extends AbstractController
{
    #[Route('/', name: 'app_blog')]
    public function index(PostRepository $postRepository, Analytics $analytics): Response
    {
        $analytics->track();
        return $this->render('blog/index.html.twig', [
            'posts' => $postRepository->findAllOrdered(),
        ]);
    }

    #[Route('/post/{post}', name: 'app_blog_post')]
    public function post(Post $post, CommentRepository $commentRepository, Analytics $analytics): Response
    {
        $analytics->track();
        return $this->render('blog/post.html.twig', [
            'post' => $post,
            'comments' => $commentRepository->findByPostOrdered($post->getId()),
        ]);
    }

    #[Route('/post/{post}/comment', name: 'app_blog_post_comment', methods: ['POST'])]
    public function comment(
        Post $post,
        Request $request,
        CommentRepository $commentRepository,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response
    {
        // If the user is not logged in, redirect to the login page
        if (!$this->getUser()) {
            return $this->redirectToRoute('app_login');
        }

        $token = new CsrfToken('comment_'.$post->getId(), (string) $request->request->get('_token'));
        if (!$csrfTokenManager->isTokenValid($token)) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('app_blog_post', ['post' => $post->getId()]);
        }

        $content = trim((string) $request->get('comment'));
        if ($content === '') {
            $this->addFlash('error', 'Comment cannot be empty');
            return $this->redirectToRoute('app_blog_post', ['post' => $post->getId()]);
        }

        $comment = new Comment();
        $comment->setPost($post);
        $comment->setAuthor($this->getUser());
        $comment->setContent($content);
        $comment->setDate(new \DateTime());
        $commentRepository->save($comment, true);

        return $this->redirectToRoute('app_blog_post', ['post' => $post->getId()]);
    }

    #[Route('/search', name: 'app_blog_post_search', methods: ['GET'])]
    public function search(Request $request, PostRepository $postRepository): Response
    {
        $search = (string) $request->get('s', '');
        $posts = $postRepository->search($search);

        return $this->render('blog/index.html.twig', [
            'search' => $search,
            'posts' => $posts,
        ]);
    }

    #[Route('/legal', name: 'app_legal')]
    public function legal(): Response
    {
        return $this->render('blog/legal.html.twig');
    }

    #[Route('/legal/content', name: 'app_legal_content', methods: ['GET'])]
    public function legalContent(Request $request): Response
    {
        $allowedFiles = ['legal.html'];
        $requested = basename((string) $request->get('p', 'legal.html'));
        if (!in_array($requested, $allowedFiles, true)) {
            throw $this->createNotFoundException();
        }

        $contentPath = realpath(__DIR__ . '/../../templates/legal/' . $requested);
        $legalDir = realpath(__DIR__ . '/../../templates/legal/');

        if ($contentPath === false || $legalDir === false || !str_starts_with($contentPath, $legalDir)) {
            throw $this->createNotFoundException();
        }

        if (!is_file($contentPath)) {
            throw $this->createNotFoundException();
        }

        return new Response((string) file_get_contents($contentPath));
    }
}
